//! The device key (§14.2): generation, secure storage, reuse and public-key
//! export.

use std::sync::{Arc, Mutex};

use pgp::composed::{
    Deserializable, KeyType, SignedKeyDetails, SignedSecretKey, SignedSecretSubKey,
};
use pgp::crypto::{
    ecc_curve::ECCCurve, hash::HashAlgorithm, public_key::PublicKeyAlgorithm,
    sym::SymmetricKeyAlgorithm,
};
use pgp::packet::{
    KeyFlags, Notation, PubKeyInner, PublicKey, PublicSubkey, SecretKey, SecretSubkey,
    SignatureConfig, SignatureType, Subpacket, SubpacketData, UserId,
};
use pgp::ser::Serialize as _;
use pgp::types::{
    CompressionAlgorithm, EcdhPublicParams, KeyDetails, KeyVersion, PacketHeaderVersion, Password,
    PublicParams, SignedUser, Tag, Timestamp,
};
use rand08::{CryptoRng, Rng};
use zeroize::Zeroizing;

use crate::crypto::{self, KeyRing, UnlockedKey};
use crate::error::{Error, Result};
use crate::util::{b64, b64_decode};

/// The RECOMMENDED placeholder user ID (§14.2.1, Appendix B).
pub const DEVICE_KEY_USER_ID: &str = "not_for_email_use@domain.tld <not_for_email_use@domain.tld>";

/// The secure-store entry holding the device key.
pub const DEVICE_KEY_ENTRY: &str = "push-device-key";

/// The platform's secure credential store (hardware-backed key store,
/// keychain, …). Values are secrets: implementations MUST keep them out of
/// the general application database, logs and backups (§14.2.2, §15).
pub trait SecureStore: Send + Sync {
    fn get(&self, name: &str) -> Result<Option<Zeroizing<String>>>;
    fn put(&self, name: &str, value: &str) -> Result<()>;
    fn delete(&self, name: &str) -> Result<()>;
}

/// A process-local [`SecureStore`]. Its contents do not survive a restart,
/// so a new device key is generated on every run; intended for tests and
/// for embedders that wrap it with their own persistence.
#[derive(Default)]
pub struct MemorySecureStore {
    entries: Mutex<std::collections::HashMap<String, Zeroizing<String>>>,
}

impl SecureStore for MemorySecureStore {
    fn get(&self, name: &str) -> Result<Option<Zeroizing<String>>> {
        Ok(self.entries.lock().expect("store lock").get(name).cloned())
    }

    fn put(&self, name: &str, value: &str) -> Result<()> {
        self.entries
            .lock()
            .expect("store lock")
            .insert(name.to_string(), Zeroizing::new(value.to_string()));
        Ok(())
    }

    fn delete(&self, name: &str) -> Result<()> {
        self.entries.lock().expect("store lock").remove(name);
        Ok(())
    }
}

/// The device key pair. The public half is derived from the private key and
/// never stored separately (§14.2.2 step 4).
pub struct DeviceKey {
    key: SignedSecretKey,
}

impl std::fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceKey")
            .field(
                "fingerprint",
                &crypto::fingerprint_hex(&self.key.to_public_key()),
            )
            .finish_non_exhaustive()
    }
}

impl DeviceKey {
    /// Generate a fresh device key as §14.2.1 lays it out, without a
    /// passphrase.
    pub fn generate() -> Result<Self> {
        let key = generate_key(rand08::thread_rng())
            .map_err(|e| Error::Crypto(format!("device key generation: {e}")))?;
        Ok(Self { key })
    }

    /// B64 of the unlocked, unarmored transferable secret key (§14.2.2).
    pub fn to_storage(&self) -> Result<Zeroizing<String>> {
        let bin = Zeroizing::new(
            self.key
                .to_bytes()
                .map_err(|e| Error::Crypto(format!("device key serialisation: {e}")))?,
        );
        Ok(Zeroizing::new(b64(&*bin)))
    }

    /// Decode a value produced by [`Self::to_storage`].
    pub fn from_storage(stored: &str) -> Result<Self> {
        let bin = Zeroizing::new(
            b64_decode(stored.trim()).map_err(|_| Error::Crypto("device key is not B64".into()))?,
        );
        let key = SignedSecretKey::from_bytes(&bin[..])
            .map_err(|e| Error::Crypto(format!("device key is unreadable: {e}")))?;
        Ok(Self { key })
    }

    /// ASCII-armored public key block for registration, ending at its last
    /// armor line (§14.2.4).
    pub fn armored_public_key(&self) -> Result<String> {
        crypto::armored_public_key(&self.key.to_public_key())
            .map(|armored| armored.trim_end().to_owned())
            .map_err(|e| Error::Crypto(format!("device public key export: {e}")))
    }

    /// Decrypt an armored OpenPGP message encrypted to this key. Signatures
    /// are not verified (§14.4.3 step 3).
    pub fn decrypt(&self, armored: &str) -> Result<Zeroizing<Vec<u8>>> {
        let ring = KeyRing::new(vec![UnlockedKey::from_unprotected(self.key.clone())]);
        let d = ring
            .decrypt(armored.as_bytes())
            .map_err(|e| Error::Crypto(format!("notification decryption failed: {e}")))?;
        Ok(Zeroizing::new(d.data))
    }
}

/// Hash algorithm of the device key's self-signatures (§14.2.1).
const SIGNATURE_HASH: HashAlgorithm = HashAlgorithm::Sha512;
/// Name of the salt notation on each self-signature (§14.2.1).
const SALT_NOTATION: &[u8] = b"salt@notations.openpgpjs.org";

/// The device key of §14.2.1: an Ed25519 primary key certifying the
/// placeholder user ID, and a Curve25519 ECDH encryption subkey whose KDF
/// uses SHA-512 and AES-256.
fn generate_key<R: Rng + CryptoRng>(mut rng: R) -> pgp::errors::Result<SignedSecretKey> {
    let created = Timestamp::now();

    let (public_params, secret_params) = KeyType::Ed25519Legacy.generate(&mut rng)?;
    let primary_public = PublicKey::from_inner(PubKeyInner::new(
        KeyVersion::V4,
        PublicKeyAlgorithm::EdDSALegacy,
        created,
        None,
        public_params,
    )?)?;
    let primary = SecretKey::new(primary_public.clone(), secret_params)?;

    let (public_params, secret_params) =
        KeyType::ECDH(ECCCurve::Curve25519Legacy).generate(&mut rng)?;
    let PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy {
        p, ecdh_kdf_type, ..
    }) = public_params
    else {
        unreachable!("a Curve25519 ECDH key has Curve25519 parameters");
    };
    let subkey_public = PublicSubkey::from_inner(PubKeyInner::new(
        KeyVersion::V4,
        PublicKeyAlgorithm::ECDH,
        created,
        None,
        PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy {
            p,
            hash: HashAlgorithm::Sha512,
            alg_sym: SymmetricKeyAlgorithm::AES256,
            ecdh_kdf_type,
        }),
    )?)?;
    let subkey = SecretSubkey::new(subkey_public.clone(), secret_params)?;

    let user_id = UserId::from_str(PacketHeaderVersion::New, DEVICE_KEY_USER_ID)?;
    let mut flags = KeyFlags::default();
    flags.set_certify(true);
    flags.set_sign(true);
    let mut features = pgp::packet::Features::default();
    features.set_seipd_v1(true);
    let mut certification = self_signature(SignatureType::CertPositive, &primary);
    certification.hashed_subpackets = vec![
        Subpacket::critical(SubpacketData::SignatureCreationTime(created))?,
        Subpacket::regular(SubpacketData::PreferredSymmetricAlgorithms(
            vec![SymmetricKeyAlgorithm::AES256, SymmetricKeyAlgorithm::AES128].into(),
        ))?,
        Subpacket::regular(SubpacketData::IssuerKeyId(primary.legacy_key_id()))?,
        salt_notation(&mut rng)?,
        Subpacket::regular(SubpacketData::PreferredHashAlgorithms(
            vec![HashAlgorithm::Sha512, HashAlgorithm::Sha256].into(),
        ))?,
        Subpacket::regular(SubpacketData::PreferredCompressionAlgorithms(
            vec![
                CompressionAlgorithm::Uncompressed,
                CompressionAlgorithm::ZLIB,
            ]
            .into(),
        ))?,
        Subpacket::regular(SubpacketData::IsPrimary(true))?,
        Subpacket::critical(SubpacketData::KeyFlags(flags))?,
        Subpacket::regular(SubpacketData::Features(features))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(primary.fingerprint()))?,
    ];
    let certification = certification.sign_certification(
        &primary,
        &primary_public,
        &Password::empty(),
        Tag::UserId,
        &user_id,
    )?;

    let mut flags = KeyFlags::default();
    flags.set_encrypt_comms(true);
    flags.set_encrypt_storage(true);
    let mut binding = self_signature(SignatureType::SubkeyBinding, &primary);
    binding.hashed_subpackets = vec![
        Subpacket::critical(SubpacketData::SignatureCreationTime(created))?,
        Subpacket::regular(SubpacketData::IssuerKeyId(primary.legacy_key_id()))?,
        salt_notation(&mut rng)?,
        Subpacket::critical(SubpacketData::KeyFlags(flags))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(primary.fingerprint()))?,
    ];
    let binding = binding.sign_subkey_binding(
        &primary,
        &primary_public,
        &Password::empty(),
        &subkey_public,
    )?;

    Ok(SignedSecretKey::new(
        primary,
        SignedKeyDetails::new(
            Vec::new(),
            Vec::new(),
            vec![SignedUser::new(user_id, vec![certification])],
            Vec::new(),
        ),
        Vec::new(),
        vec![SignedSecretSubKey::new(subkey, vec![binding])],
    ))
}

fn self_signature(typ: SignatureType, primary: &SecretKey) -> SignatureConfig {
    SignatureConfig::v4(typ, primary.algorithm(), SIGNATURE_HASH)
}

/// A salt notation as long as the signature hash's salt (§14.2.1).
fn salt_notation<R: Rng + CryptoRng>(rng: &mut R) -> pgp::errors::Result<Subpacket> {
    let mut salt = vec![0u8; SIGNATURE_HASH.salt_len().unwrap_or(16)];
    rng.fill_bytes(&mut salt);
    Subpacket::regular(SubpacketData::Notation(Notation {
        readable: false,
        name: SALT_NOTATION.into(),
        value: salt.into(),
    }))
}

/// Loads, creates and reuses the one device key of this installation
/// (§14.2.3). Shared by every Account.
pub struct DeviceKeyManager {
    store: Arc<dyn SecureStore>,
    create_lock: Mutex<()>,
}

impl DeviceKeyManager {
    pub fn new(store: Arc<dyn SecureStore>) -> Self {
        Self {
            store,
            create_lock: Mutex::new(()),
        }
    }

    /// The stored key, if any. Used on receipt: a missing key is never
    /// regenerated there (§14.4.3 step 1).
    pub fn load(&self) -> Result<Option<DeviceKey>> {
        match self.store.get(DEVICE_KEY_ENTRY)? {
            Some(v) => DeviceKey::from_storage(&v).map(Some),
            None => Ok(None),
        }
    }

    /// The stored key, generating and storing a new one if none exists.
    /// Used for registration.
    pub fn get_or_create(&self) -> Result<DeviceKey> {
        let _guard = self.create_lock.lock().expect("device key lock");
        if let Some(k) = self.load()? {
            return Ok(k);
        }
        let key = DeviceKey::generate()?;
        self.store.put(DEVICE_KEY_ENTRY, &key.to_storage()?)?;
        tracing::info!("generated a new push device key");
        Ok(key)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use pgp::composed::{MessageBuilder, SignedPublicKey};
    use pgp::crypto::sym::SymmetricKeyAlgorithm;

    /// Encrypt like the Service does (§14.4.2): literal data, no signature,
    /// armored.
    pub(crate) fn service_encrypt(public_armored: &str, plain: &[u8]) -> String {
        let pk = crypto::parse_public_key(public_armored.as_bytes()).unwrap();
        encrypt_to(&pk, plain)
    }

    fn encrypt_to(pk: &SignedPublicKey, plain: &[u8]) -> String {
        let mut b = MessageBuilder::from_bytes("", plain.to_vec())
            .seipd_v1(rand08::thread_rng(), SymmetricKeyAlgorithm::AES256);
        match crypto::encryption_key(pk).unwrap() {
            crypto::EncTarget::Subkey(k) => b.encrypt_to_key(rand08::thread_rng(), k).unwrap(),
            crypto::EncTarget::Primary(k) => b.encrypt_to_key(rand08::thread_rng(), k).unwrap(),
        };
        b.to_armored_string(rand08::thread_rng(), Default::default())
            .unwrap()
    }

    /// Generated keys are laid out as §14.2.1 requires, and exported as
    /// §14.2.4 requires.
    #[test]
    fn generated_keys_follow_the_profile() {
        let armored = DeviceKey::generate().unwrap().armored_public_key().unwrap();
        assert!(armored.ends_with("-----END PGP PUBLIC KEY BLOCK-----"));
        let pk = crypto::parse_public_key(armored.as_bytes()).unwrap();
        pk.verify_bindings().unwrap();
        let user = &pk.details.users[0];
        assert_eq!(user.id.id(), DEVICE_KEY_USER_ID.as_bytes());
        let certification = &user.signatures[0];
        let binding = &pk.public_subkeys[0].signatures[0];
        for sig in [certification, binding] {
            assert_eq!(sig.hash_alg(), Some(HashAlgorithm::Sha512));
            let salt = sig
                .notations()
                .into_iter()
                .find(|n| n.name.as_ref() == SALT_NOTATION)
                .expect("salt notation");
            assert_eq!(salt.value.len(), 32);
        }
        assert_eq!(
            certification.preferred_symmetric_algs(),
            &[SymmetricKeyAlgorithm::AES256, SymmetricKeyAlgorithm::AES128]
        );
        assert_eq!(
            certification.preferred_hash_algs(),
            &[HashAlgorithm::Sha512, HashAlgorithm::Sha256]
        );
        assert_eq!(
            certification.preferred_compression_algs(),
            &[
                CompressionAlgorithm::Uncompressed,
                CompressionAlgorithm::ZLIB
            ]
        );
        match pk.public_subkeys[0].key.public_params() {
            PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy { hash, alg_sym, .. }) => {
                assert_eq!(*hash, HashAlgorithm::Sha512);
                assert_eq!(*alg_sym, SymmetricKeyAlgorithm::AES256);
            }
            other => panic!("unexpected subkey: {other:?}"),
        }
    }

    #[test]
    fn storage_roundtrip_and_decrypt() {
        let k = DeviceKey::generate().unwrap();
        let stored = k.to_storage().unwrap();
        let k2 = DeviceKey::from_storage(&stored).unwrap();
        let pub_armored = k2.armored_public_key().unwrap();
        assert!(pub_armored.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        let pk = crypto::parse_public_key(pub_armored.as_bytes()).unwrap();
        assert_eq!(
            crypto::first_identity_name(&pk),
            "not_for_email_use@domain.tld"
        );
        let msg = service_encrypt(&pub_armored, br#"{"type":"email"}"#);
        assert!(msg.starts_with("-----BEGIN PGP MESSAGE-----"));
        assert_eq!(&*k.decrypt(&msg).unwrap(), br#"{"type":"email"}"#);
    }

    #[test]
    fn manager_reuses_and_regenerates() {
        let store = Arc::new(MemorySecureStore::default());
        let m = DeviceKeyManager::new(store.clone());
        assert!(m.load().unwrap().is_none());
        let a = m.get_or_create().unwrap().armored_public_key().unwrap();
        let b = m.get_or_create().unwrap().armored_public_key().unwrap();
        assert_eq!(a, b);
        store.delete(DEVICE_KEY_ENTRY).unwrap();
        let c = m.get_or_create().unwrap().armored_public_key().unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn garbage_is_a_crypto_error() {
        assert!(matches!(
            DeviceKey::from_storage("!!"),
            Err(Error::Crypto(_))
        ));
        assert!(matches!(
            DeviceKey::from_storage("AAAA"),
            Err(Error::Crypto(_))
        ));
    }
}
