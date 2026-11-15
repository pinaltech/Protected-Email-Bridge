//! Key salts, salted key passphrases and key ring unlocking (§6).

use tracing::warn;
use zeroize::Zeroizing;

use crate::api::types::{Key, KeySalt};
use crate::crypto::{KeyRing, UnlockedKey};
use crate::error::{Error, Result};
use crate::srp::bcrypt_raw_salt;
use crate::util::b64_decode;

/// Derive the salted key passphrase for key `key_id` (§6.2): the last 31
/// octets of `bcrypt(keyPassword, R64(B64decode(KeySalt)))`.
pub fn salted_key_passphrase(
    key_password: &[u8],
    salts: &[KeySalt],
    key_id: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let entry = salts
        .iter()
        .find(|s| s.id == key_id)
        .ok_or_else(|| Error::NotFound(format!("no key salt for key {key_id}")))?;
    let salt = b64_decode(&entry.key_salt)?;
    if salt.len() != 16 {
        return Err(Error::Invalid(format!(
            "key salt has {} octets, expected 16",
            salt.len()
        )));
    }
    let mut s16 = [0u8; 16];
    s16.copy_from_slice(&salt);
    let full = bcrypt_raw_salt(key_password, s16)?;
    let bytes = full.as_bytes();
    Ok(Zeroizing::new(bytes[bytes.len() - 31..].to_vec()))
}

/// The user's primary key (`Primary = 1`), falling back to the first key.
pub fn primary_key(keys: &[Key]) -> Option<&Key> {
    keys.iter().find(|k| k.primary).or_else(|| keys.first())
}

/// Unlock the User key ring (§6.3). At least one key must unlock.
pub fn unlock_user_keyring(keys: &[Key], passphrase: &[u8]) -> Result<KeyRing> {
    let mut ring = Vec::new();
    for k in keys.iter().filter(|k| k.active) {
        match UnlockedKey::unlock(&k.private_key, passphrase) {
            Ok(u) => ring.push(u),
            Err(e) => warn!(key = %k.id, "user key failed to unlock: {e}"),
        }
    }
    if ring.is_empty() {
        return Err(Error::KeyUnlock);
    }
    Ok(KeyRing::new(ring))
}

/// Unlock an Address key ring (§6.3). The result may be empty: such an
/// address is unusable.
pub fn unlock_address_keyring(keys: &[Key], user_ring: &KeyRing, passphrase: &[u8]) -> KeyRing {
    let mut ring = Vec::new();
    for k in keys.iter().filter(|k| k.active) {
        let pass: Result<Zeroizing<Vec<u8>>> = if !k.token.is_empty() && !k.signature.is_empty() {
            user_ring.decrypt(k.token.as_bytes()).and_then(|d| {
                user_ring.verify_detached(&d.data, k.signature.as_bytes())?;
                Ok(Zeroizing::new(d.data))
            })
        } else {
            Ok(Zeroizing::new(passphrase.to_vec()))
        };
        match pass.and_then(|p| UnlockedKey::unlock(&k.private_key, &p)) {
            Ok(u) => ring.push(u),
            Err(e) => warn!(key = %k.id, "address key failed to unlock: {e}"),
        }
    }
    KeyRing::new(ring)
}
