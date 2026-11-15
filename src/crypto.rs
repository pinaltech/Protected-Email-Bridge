//! OpenPGP lifecycle (§9) on top of rPGP.
//!
//! Profile (§9.1): AES-256 for every new encryption, no compression,
//! SHA-256 signatures, Ed25519/X25519 support.

use std::io::{BufReader, Read};

use pgp::armor::{BlockType, Dearmor, Headers};
use pgp::composed::{
    CleartextSignedMessage, Deserializable, DetachedSignature, Message, MessageBuilder,
    PlainSessionKey, RawSessionKey, SignedPublicKey, SignedSecretKey,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::PublicKeyEncryptedSessionKey;
use pgp::ser::Serialize;
use pgp::types::{DecryptionKey, EskType, KeyDetails, Password, SigningKey};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::util::b64;

fn rng() -> rand08::rngs::ThreadRng {
    rand08::thread_rng()
}

fn pw(bytes: &[u8]) -> Password {
    Password::from(bytes)
}

// ---------------------------------------------------------------------------
// Armor helpers
// ---------------------------------------------------------------------------

struct RawPackets<'a>(&'a [u8]);

impl Serialize for RawPackets<'_> {
    fn to_writer<W: std::io::Write>(&self, w: &mut W) -> pgp::errors::Result<()> {
        w.write_all(self.0)?;
        Ok(())
    }
    fn write_len(&self) -> usize {
        self.0.len()
    }
}

/// Armor binary OpenPGP data as a `PGP MESSAGE`, optionally with a
/// `Comment:` header (§9.9).
pub fn armor_message(data: &[u8], comment: Option<&str>) -> Result<String> {
    armor(data, BlockType::Message, comment)
}

/// Armor a binary signature as a `PGP SIGNATURE`.
pub fn armor_signature(data: &[u8]) -> Result<String> {
    armor(data, BlockType::Signature, None)
}

fn armor(data: &[u8], typ: BlockType, comment: Option<&str>) -> Result<String> {
    let mut headers = Headers::new();
    if let Some(c) = comment {
        headers.insert("Comment".into(), vec![c.to_string()]);
    }
    let mut out = Vec::new();
    pgp::armor::write(
        &RawPackets(data),
        typ,
        &mut out,
        comment.map(|_| &headers),
        true,
    )?;
    String::from_utf8(out).map_err(|e| Error::Pgp(e.to_string()))
}

/// Dearmor any armored OpenPGP block into its binary content.
pub fn dearmor(text: &[u8]) -> Result<Vec<u8>> {
    let mut d = Dearmor::new(BufReader::new(text));
    let mut out = Vec::new();
    d.read_to_end(&mut out)?;
    Ok(out)
}

/// Accept either armored or binary input and return binary.
pub fn to_binary(data: &[u8]) -> Result<Vec<u8>> {
    let trimmed = data.trim_ascii_start();
    if trimmed.starts_with(b"-----BEGIN PGP") {
        dearmor(trimmed)
    } else {
        Ok(data.to_vec())
    }
}

// ---------------------------------------------------------------------------
// Packet splitting
// ---------------------------------------------------------------------------

/// Parse one OpenPGP packet header at `data[pos..]`, returning
/// `(tag, total_packet_len_including_header)`. Partial body lengths are
/// followed to the end of the packet.
fn packet_extent(data: &[u8], pos: usize) -> Result<(u8, usize)> {
    let bad = || Error::Pgp("malformed packet header".into());
    let first = *data.get(pos).ok_or_else(bad)?;
    if first & 0x80 == 0 {
        return Err(bad());
    }
    if first & 0x40 != 0 {
        // New format.
        let tag = first & 0x3f;
        let mut p = pos + 1;
        loop {
            let o1 = *data.get(p).ok_or_else(bad)? as usize;
            if o1 < 192 {
                p += 1 + o1;
                break;
            } else if o1 < 224 {
                let o2 = *data.get(p + 1).ok_or_else(bad)? as usize;
                p += 2 + ((o1 - 192) << 8) + o2 + 192;
                break;
            } else if o1 == 255 {
                let b = data.get(p + 1..p + 5).ok_or_else(bad)?;
                let len = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
                p += 5 + len;
                break;
            } else {
                // Partial body length: continue with the next length header.
                let len = 1usize << (o1 & 0x1f);
                p += 1 + len;
            }
        }
        if p > data.len() {
            return Err(bad());
        }
        Ok((tag, p - pos))
    } else {
        // Old format.
        let tag = (first >> 2) & 0x0f;
        let (hlen, blen) = match first & 0x03 {
            0 => (2, *data.get(pos + 1).ok_or_else(bad)? as usize),
            1 => {
                let b = data.get(pos + 1..pos + 3).ok_or_else(bad)?;
                (3, u16::from_be_bytes([b[0], b[1]]) as usize)
            }
            2 => {
                let b = data.get(pos + 1..pos + 5).ok_or_else(bad)?;
                (5, u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
            }
            _ => (1, data.len() - pos - 1),
        };
        let total = hlen + blen;
        if pos + total > data.len() {
            return Err(bad());
        }
        Ok((tag, total))
    }
}

/// Split a binary encrypted message into its key packets (PKESK/SKESK) and
/// the data packet (SEIPD and anything after it).
pub fn split_message(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut pos = 0;
    while pos < data.len() {
        let (tag, len) = packet_extent(data, pos)?;
        if tag == 1 || tag == 3 {
            pos += len;
        } else {
            break;
        }
    }
    if pos == 0 || pos >= data.len() {
        return Err(Error::Pgp(
            "message has no key packets or no data packet".into(),
        ));
    }
    Ok((data[..pos].to_vec(), data[pos..].to_vec()))
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// Parse an armored or binary secret key.
pub fn parse_secret_key(data: &[u8]) -> Result<SignedSecretKey> {
    let bin = to_binary(data)?;
    Ok(SignedSecretKey::from_bytes(&bin[..])?)
}

/// Parse an armored or binary public key.
pub fn parse_public_key(data: &[u8]) -> Result<SignedPublicKey> {
    let bin = to_binary(data)?;
    Ok(SignedPublicKey::from_bytes(&bin[..])?)
}

/// Uppercase hex fingerprint of a public key.
pub fn fingerprint_hex(key: &SignedPublicKey) -> String {
    hex::encode_upper(key.fingerprint().as_bytes())
}

/// Lowercase hex fingerprints of the primary key and every subkey.
pub fn all_fingerprints(key: &SignedPublicKey) -> Vec<String> {
    let mut v = vec![hex::encode(key.fingerprint().as_bytes())];
    v.extend(
        key.public_subkeys
            .iter()
            .map(|s| hex::encode(s.key.fingerprint().as_bytes())),
    );
    v
}

/// Armored public key.
pub fn armored_public_key(key: &SignedPublicKey) -> Result<String> {
    Ok(key.to_armored_string(Default::default())?)
}

/// First user ID's name component (used for the public-key attachment name).
pub fn first_identity_name(key: &SignedPublicKey) -> String {
    key.details
        .users
        .first()
        .map(|u| {
            let id = String::from_utf8_lossy(u.id.id()).to_string();
            match id.split_once('<') {
                Some((name, _)) => name.trim().to_string(),
                None => id,
            }
        })
        .unwrap_or_default()
}

/// An encryption-capable key component.
#[derive(Clone, Copy)]
pub enum EncTarget<'a> {
    Subkey(&'a pgp::packet::PublicSubkey),
    Primary(&'a pgp::packet::PublicKey),
}

impl EncTarget<'_> {
    /// Encrypt a session key to this component as a v3 PKESK.
    pub fn pkesk(&self, sk: &SessionKey) -> Result<PublicKeyEncryptedSessionKey> {
        let raw = RawSessionKey::from(sk.key.to_vec());
        Ok(match self {
            EncTarget::Subkey(k) => {
                PublicKeyEncryptedSessionKey::from_session_key_v3(rng(), &raw, sk.algorithm, *k)?
            }
            EncTarget::Primary(k) => {
                PublicKeyEncryptedSessionKey::from_session_key_v3(rng(), &raw, sk.algorithm, *k)?
            }
        })
    }
}

/// Pick a key suitable for encryption from a public certificate.
pub fn encryption_key(key: &SignedPublicKey) -> Result<EncTarget<'_>> {
    for sk in &key.public_subkeys {
        if sk.key.algorithm().can_encrypt() {
            return Ok(EncTarget::Subkey(&sk.key));
        }
    }
    if key.primary_key.algorithm().can_encrypt() {
        return Ok(EncTarget::Primary(&key.primary_key));
    }
    Err(Error::Pgp("key has no encryption-capable component".into()))
}

/// A symmetric session key.
#[derive(Clone)]
pub struct SessionKey {
    pub algorithm: SymmetricKeyAlgorithm,
    pub key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

impl SessionKey {
    /// Wire name of the algorithm (`"aes256"` etc.).
    pub fn algorithm_name(&self) -> &'static str {
        match self.algorithm {
            SymmetricKeyAlgorithm::AES128 => "aes128",
            SymmetricKeyAlgorithm::AES192 => "aes192",
            SymmetricKeyAlgorithm::AES256 => "aes256",
            SymmetricKeyAlgorithm::TripleDES => "3des",
            SymmetricKeyAlgorithm::CAST5 => "cast5",
            _ => "aes256",
        }
    }

    /// Base64 of the raw key.
    pub fn key_b64(&self) -> String {
        b64(&*self.key)
    }

    /// Encrypt this session key to a recipient's public key, returning a
    /// binary PKESK packet.
    pub fn encrypt_to(&self, key: &SignedPublicKey) -> Result<Vec<u8>> {
        let enc = encryption_key(key)?;
        let pkesk = enc.pkesk(self)?;
        let mut out = Vec::new();
        pgp::packet::PacketTrait::to_writer_with_header(&pkesk, &mut out)?;
        Ok(out)
    }
}

/// A secret key together with the passphrase that unlocks it.
pub struct UnlockedKey {
    pub key: SignedSecretKey,
    passphrase: Zeroizing<Vec<u8>>,
}

impl UnlockedKey {
    /// Unlock and integrity-check a key (§6.3): the passphrase must decrypt
    /// the secret material, and a test signature produced with it must
    /// verify against the public key.
    pub fn unlock(armored: &str, passphrase: &[u8]) -> Result<Self> {
        let key = parse_secret_key(armored.as_bytes())?;
        key.primary_key
            .unlock(&pw(passphrase), |_, _| Ok(()))
            .map_err(|_| Error::KeyUnlock)?
            .map_err(|_| Error::KeyUnlock)?;
        for sk in &key.secret_subkeys {
            sk.key
                .unlock(&pw(passphrase), |_, _| Ok(()))
                .map_err(|_| Error::KeyUnlock)?
                .map_err(|_| Error::KeyUnlock)?;
        }
        let k = Self {
            key,
            passphrase: Zeroizing::new(passphrase.to_vec()),
        };
        // Private/public consistency check.
        let probe = b"key-integrity-probe";
        let sig = k.sign_detached(probe)?;
        verify_detached_with(&k.public_key(), probe, &sig)?;
        Ok(k)
    }

    pub fn public_key(&self) -> SignedPublicKey {
        self.key.to_public_key()
    }

    pub fn password(&self) -> Password {
        pw(&self.passphrase)
    }

    fn signing_key(&self) -> Result<&dyn SigningKey> {
        if self.key.primary_key.algorithm().can_sign() {
            return Ok(&self.key.primary_key);
        }
        for sk in &self.key.secret_subkeys {
            if sk.key.algorithm().can_sign() {
                return Ok(&sk.key);
            }
        }
        Err(Error::Pgp("key has no signing-capable component".into()))
    }

    fn encryption_key(&self) -> Result<EncTarget<'_>> {
        for sk in &self.key.secret_subkeys {
            if sk.key.algorithm().can_encrypt() {
                return Ok(EncTarget::Subkey(sk.key.public_key()));
            }
        }
        if self.key.primary_key.algorithm().can_encrypt() {
            return Ok(EncTarget::Primary(self.key.primary_key.public_key()));
        }
        Err(Error::Pgp("key has no encryption-capable component".into()))
    }

    /// Binary detached signature (SHA-256) over `data`.
    pub fn sign_detached(&self, data: &[u8]) -> Result<Vec<u8>> {
        let sig = DetachedSignature::sign_binary_data(
            rng(),
            &SigningKeyRef(self.signing_key()?),
            &self.password(),
            HashAlgorithm::Sha256,
            data,
        )?;
        Ok(sig.to_bytes()?)
    }

    /// Try to decrypt a PKESK with this key.
    fn decrypt_pkesk(&self, pkesk: &PublicKeyEncryptedSessionKey) -> Option<PlainSessionKey> {
        let values = pkesk.values().ok()?;
        let password = self.password();
        let try_key = |k: &dyn DecryptionKey, matches: bool| -> Option<PlainSessionKey> {
            if !matches {
                return None;
            }
            match k.decrypt(&password, values, EskType::V3_4) {
                Ok(Ok(sk)) => Some(sk),
                _ => None,
            }
        };
        if let Some(sk) = try_key(
            &self.key.primary_key,
            pkesk.match_identity(self.key.primary_key.public_key()),
        ) {
            return Some(sk);
        }
        for sub in &self.key.secret_subkeys {
            if let Some(sk) = try_key(&sub.key, pkesk.match_identity(sub.key.public_key())) {
                return Some(sk);
            }
        }
        None
    }
}

/// Wrapper making `&dyn SigningKey` usable where `impl SigningKey` is needed.
#[derive(Debug)]
struct SigningKeyRef<'a>(&'a dyn SigningKey);

impl KeyDetails for SigningKeyRef<'_> {
    fn version(&self) -> pgp::types::KeyVersion {
        self.0.version()
    }
    fn fingerprint(&self) -> pgp::types::Fingerprint {
        self.0.fingerprint()
    }
    fn legacy_key_id(&self) -> pgp::types::KeyId {
        self.0.legacy_key_id()
    }
    fn algorithm(&self) -> pgp::crypto::public_key::PublicKeyAlgorithm {
        self.0.algorithm()
    }
    fn created_at(&self) -> pgp::types::Timestamp {
        self.0.created_at()
    }
    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        self.0.legacy_v3_expiration_days()
    }
    fn public_params(&self) -> &pgp::types::PublicParams {
        self.0.public_params()
    }
}

impl SigningKey for SigningKeyRef<'_> {
    fn sign(
        &self,
        key_pw: &Password,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> pgp::errors::Result<pgp::types::SignatureBytes> {
        self.0.sign(key_pw, hash, data)
    }
    fn hash_alg(&self) -> HashAlgorithm {
        self.0.hash_alg()
    }
}

/// Verify a binary or armored detached signature over `data`, trying the
/// primary key and each subkey.
pub fn verify_detached_with(key: &SignedPublicKey, data: &[u8], sig: &[u8]) -> Result<()> {
    let bin = to_binary(sig)?;
    let sig = DetachedSignature::from_bytes(&bin[..])?;
    if sig.verify(key, data).is_ok() {
        return Ok(());
    }
    for sk in &key.public_subkeys {
        if sig.verify(&sk.key, data).is_ok() {
            return Ok(());
        }
    }
    Err(Error::Pgp("signature verification failed".into()))
}

/// Verify a cleartext-signed message (§5.1.2) and return the cleartext.
/// Aborts if any data follows the signature block.
pub fn verify_cleartext(armored: &str, key: &SignedPublicKey) -> Result<String> {
    const END: &str = "-----END PGP SIGNATURE-----";
    let end = armored
        .find(END)
        .ok_or_else(|| Error::Pgp("missing signature block".into()))?;
    if !armored[end + END.len()..].trim().is_empty() {
        return Err(Error::Pgp("data after signature block".into()));
    }
    let (msg, _) = CleartextSignedMessage::from_string(armored)?;
    let ok = msg.verify(key).is_ok()
        || key
            .public_subkeys
            .iter()
            .any(|sk| msg.verify(&sk.key).is_ok());
    if !ok {
        return Err(Error::Pgp("cleartext signature verification failed".into()));
    }
    Ok(msg.signed_text())
}

/// Result of a decryption.
#[derive(Debug)]
pub struct Decrypted {
    pub data: Vec<u8>,
    /// First embedded signature: (binary signature packet, hash name).
    pub signature: Option<(Vec<u8>, String)>,
}

/// Display name of a hash algorithm, as reported for `micalg` (§11.8.3).
pub fn hash_name(h: HashAlgorithm) -> String {
    match h {
        HashAlgorithm::Md5 => "MD5".into(),
        HashAlgorithm::Sha1 => "SHA-1".into(),
        HashAlgorithm::Ripemd160 => "RIPEMD-160".into(),
        HashAlgorithm::Sha256 => "SHA-256".into(),
        HashAlgorithm::Sha384 => "SHA-384".into(),
        HashAlgorithm::Sha512 => "SHA-512".into(),
        HashAlgorithm::Sha224 => "SHA-224".into(),
        HashAlgorithm::Sha3_256 => "SHA3-256".into(),
        HashAlgorithm::Sha3_512 => "SHA3-512".into(),
        other => format!("{other:?}").to_uppercase(),
    }
}

/// An ordered set of unlocked keys (User or Address key ring, §6.3).
#[derive(Default)]
pub struct KeyRing {
    pub keys: Vec<UnlockedKey>,
}

impl KeyRing {
    pub fn new(keys: Vec<UnlockedKey>) -> Self {
        Self { keys }
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// "The first key" (§6.3).
    pub fn first(&self) -> Result<&UnlockedKey> {
        self.keys
            .first()
            .ok_or_else(|| Error::Pgp("key ring is empty".into()))
    }

    /// Decrypt a binary or armored OpenPGP message. Signatures are not
    /// verified (§9.2); the first embedded signature, if any, is extracted.
    pub fn decrypt(&self, data: &[u8]) -> Result<Decrypted> {
        let bin = to_binary(data)?;
        let msg = Message::from_bytes(&bin[..])?;
        let passwords: Vec<Password> = self.keys.iter().map(|k| k.password()).collect();
        let msg = msg.decrypt_with_keys(
            passwords.iter().collect(),
            self.keys.iter().map(|k| &k.key).collect(),
        )?;
        let mut msg = if msg.is_compressed() {
            msg.decompress()?
        } else {
            msg
        };
        let data = msg.as_data_vec()?;
        let signature = match &msg {
            Message::Signed { reader, .. } => reader.signature(0).and_then(|s| {
                let hash = s
                    .hash_alg()
                    .map(hash_name)
                    .unwrap_or_else(|| "SHA-256".into());
                DetachedSignature::new(s.clone())
                    .to_bytes()
                    .ok()
                    .map(|b| (b, hash))
            }),
            _ => None,
        };
        Ok(Decrypted { data, signature })
    }

    /// Recover the session key from binary key packets (§9.5 step 4, §9.7
    /// step 3).
    pub fn decrypt_session_key(&self, key_packets: &[u8]) -> Result<SessionKey> {
        let mut pos = 0;
        while pos < key_packets.len() {
            let (tag, len) = packet_extent(key_packets, pos)?;
            if tag == 1 {
                let pkt = &key_packets[pos..pos + len];
                let parsed = pgp::packet::PacketParser::new(BufReader::new(pkt)).next();
                if let Some(Ok(pgp::packet::Packet::PublicKeyEncryptedSessionKey(pkesk))) = parsed {
                    for k in &self.keys {
                        if let Some(PlainSessionKey::V3_4 { sym_alg, ref key }) =
                            k.decrypt_pkesk(&pkesk)
                        {
                            return Ok(SessionKey {
                                algorithm: sym_alg,
                                key: Zeroizing::new(key.as_ref().to_vec()),
                            });
                        }
                    }
                }
            }
            pos += len;
        }
        Err(Error::Pgp("no key packet could be decrypted".into()))
    }

    /// Encrypt `data` to the first key (AES-256, uncompressed), optionally
    /// signing with the first key. Returns the binary message and the
    /// session key used.
    pub fn encrypt(
        &self,
        data: &[u8],
        sign: bool,
        filename: &str,
    ) -> Result<(Vec<u8>, SessionKey)> {
        let first = self.first()?;
        let mut builder = MessageBuilder::from_bytes(filename.to_string(), data.to_vec())
            .seipd_v1(rng(), SymmetricKeyAlgorithm::AES256);
        match first.encryption_key()? {
            EncTarget::Subkey(k) => builder.encrypt_to_key(rng(), k)?,
            EncTarget::Primary(k) => builder.encrypt_to_key(rng(), k)?,
        };
        let session = SessionKey {
            algorithm: SymmetricKeyAlgorithm::AES256,
            key: Zeroizing::new(builder.session_key().as_ref().to_vec()),
        };
        if sign {
            builder.sign(
                first.signing_key()?,
                first.password(),
                HashAlgorithm::Sha256,
            );
        }
        let out = builder.to_vec(rng())?;
        Ok((out, session))
    }

    /// Encrypt and armor (optionally signed).
    pub fn encrypt_armored(&self, data: &[u8], sign: bool) -> Result<String> {
        let (bin, _) = self.encrypt(data, sign, "")?;
        armor_message(&bin, None)
    }

    /// Verify a detached signature against any key in the ring.
    pub fn verify_detached(&self, data: &[u8], sig: &[u8]) -> Result<()> {
        for k in &self.keys {
            if verify_detached_with(&k.public_key(), data, sig).is_ok() {
                return Ok(());
            }
        }
        Err(Error::Pgp("signature verification failed".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_simple() {
        // Two fake new-format packets: tag 1 (len 3) then tag 18 (len 2).
        let data = [0xC1, 3, 1, 2, 3, 0xD2, 2, 9, 9];
        let (k, d) = split_message(&data).unwrap();
        assert_eq!(k, vec![0xC1, 3, 1, 2, 3]);
        assert_eq!(d, vec![0xD2, 2, 9, 9]);
    }

    #[test]
    fn armor_roundtrip() {
        let a = armor_message(b"\xC1\x01\x00", Some("hello")).unwrap();
        assert!(a.contains("Comment: hello"));
        assert_eq!(dearmor(a.as_bytes()).unwrap(), b"\xC1\x01\x00");
    }
}
