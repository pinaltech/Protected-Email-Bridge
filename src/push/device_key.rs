//! The device key (§14.2): generation, secure storage, reuse and public-key
//! export.

use std::sync::{Arc, Mutex};

use pgp::composed::{
    Deserializable, EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedSecretKey,
    SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::ser::Serialize as _;
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
    /// Generate a fresh Ed25519 primary key with a Curve25519 ECDH
    /// encryption subkey, without a passphrase (§14.2.1).
    pub fn generate() -> Result<Self> {
        let mut enc = SubkeyParamsBuilder::default();
        enc.key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
            .can_sign(false)
            .can_encrypt(EncryptionCaps::All)
            .can_authenticate(false)
            .passphrase(None);
        let mut params = SecretKeyParamsBuilder::default();
        params
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(true)
            .can_encrypt(EncryptionCaps::None)
            .primary_user_id(DEVICE_KEY_USER_ID.into())
            .passphrase(None)
            .subkeys(vec![enc.build().map_err(|e| {
                Error::Crypto(format!("device subkey parameters: {e}"))
            })?]);
        let key = params
            .build()
            .map_err(|e| Error::Crypto(format!("device key parameters: {e}")))?
            .generate(rand08::thread_rng())
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

    /// ASCII-armored public key block for registration (§14.2.4).
    pub fn armored_public_key(&self) -> Result<String> {
        crypto::armored_public_key(&self.key.to_public_key())
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
