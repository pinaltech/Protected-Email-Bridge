//! Local credentials, accounts, address modes and persisted state (§10).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::api::types::Address;
use crate::config::limits::GATEWAY_PASSWORD_LEN;
use crate::error::{Error, Result};
use crate::util::{b64, b64_decode, b64url_np, b64url_np_decode, random_bytes};

/// The Gateway password secret (§10.1).
#[derive(Clone)]
pub struct GatewayPassword(Zeroizing<Vec<u8>>);

impl std::fmt::Debug for GatewayPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GatewayPassword(..)")
    }
}

impl GatewayPassword {
    /// 16 random octets from a CSPRNG.
    pub fn generate() -> Self {
        Self(Zeroizing::new(random_bytes(GATEWAY_PASSWORD_LEN)))
    }

    pub fn from_bytes(b: &[u8]) -> Self {
        Self(Zeroizing::new(b.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The string presented to the user (B64URL-NP, 22 characters).
    pub fn display(&self) -> String {
        b64url_np(&*self.0)
    }

    /// Constant-time check of a client-supplied password.
    pub fn verify(&self, supplied: &str) -> bool {
        match b64url_np_decode(supplied.trim()) {
            Ok(d) => d.len() == self.0.len() && bool::from(d.ct_eq(&self.0)),
            Err(_) => false,
        }
    }
}

/// Address mode (§10.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum AddressMode {
    #[default]
    Combined,
    Split,
}

/// Initial-sync progress (§10.4).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncProgress {
    pub labels_done: bool,
    pub messages_done: bool,
    pub last_synced_message_id: Option<String>,
    pub failed_message_ids: BTreeSet<String>,
    pub start_event_id: Option<String>,
}

impl SyncProgress {
    pub fn is_complete(&self) -> bool {
        self.labels_done && self.messages_done
    }
}

/// Per-account persisted state (§10.4). Secrets are stored Base64-encoded
/// inside the encrypted container.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistedAccount {
    pub user_id: String,
    pub username: String,
    pub primary_email: String,
    pub session_uid: String,
    pub refresh_token: String,
    pub salted_key_passphrase: String,
    pub gateway_password: String,
    pub address_mode: AddressMode,
    pub last_event_id: Option<String>,
    pub sync: SyncProgress,
    pub cache_key: String,
}

impl PersistedAccount {
    pub fn new(user_id: &str, username: &str, primary_email: &str, gw: &GatewayPassword) -> Self {
        Self {
            user_id: user_id.into(),
            username: username.into(),
            primary_email: primary_email.into(),
            gateway_password: b64(gw.as_bytes()),
            cache_key: b64(random_bytes(32)),
            ..Default::default()
        }
    }

    pub fn gateway_password(&self) -> Result<GatewayPassword> {
        Ok(GatewayPassword::from_bytes(&b64_decode(
            &self.gateway_password,
        )?))
    }

    pub fn salted_key_passphrase(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(b64_decode(&self.salted_key_passphrase)?))
    }

    pub fn set_salted_key_passphrase(&mut self, p: &[u8]) {
        self.salted_key_passphrase = b64(p);
    }

    /// Clear the stored session (refresh token invalid, §5.5.1).
    pub fn clear_session(&mut self) {
        self.session_uid.clear();
        self.refresh_token.clear();
    }

    pub fn is_signed_in(&self) -> bool {
        !self.session_uid.is_empty() && !self.refresh_token.is_empty()
    }
}

/// Archive mapping SHA-256(primary email) to the gateway password secret, so
/// that client configuration survives logout/login (§10.1 step 4).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PasswordArchive {
    entries: BTreeMap<String, String>,
}

impl PasswordArchive {
    fn key(email: &str) -> String {
        hex::encode(Sha256::digest(email.trim().to_lowercase().as_bytes()))
    }

    pub fn remember(&mut self, primary_email: &str, gw: &GatewayPassword) {
        self.entries
            .insert(Self::key(primary_email), b64(gw.as_bytes()));
    }

    /// The archived secret, or a newly generated one.
    pub fn get_or_generate(&mut self, primary_email: &str) -> GatewayPassword {
        if let Some(gw) = self
            .entries
            .get(&Self::key(primary_email))
            .and_then(|v| b64_decode(v).ok())
        {
            return GatewayPassword::from_bytes(&gw);
        }
        let gw = GatewayPassword::generate();
        self.remember(primary_email, &gw);
        gw
    }
}

/// Client authentication rule (§10.2): the password must match the
/// account's gateway password and the username must equal (case-insensitive,
/// no `+tag` stripping) the email of an enabled address. Returns the
/// matching address.
pub fn authenticate_client<'a>(
    gw: &GatewayPassword,
    addresses: &'a [Address],
    username: &str,
    password: &str,
) -> Option<&'a Address> {
    let pw_ok = gw.verify(password);
    let addr = addresses
        .iter()
        .find(|a| a.is_enabled() && a.email.eq_ignore_ascii_case(username.trim()));
    if pw_ok { addr } else { None }
}

/// Storage of persisted account state.
pub trait StateStore: Send + Sync {
    fn load_all(&self) -> Result<Vec<PersistedAccount>>;
    fn save(&self, account: &PersistedAccount) -> Result<()>;
    fn delete(&self, user_id: &str) -> Result<()>;
    fn load_archive(&self) -> Result<PasswordArchive>;
    fn save_archive(&self, archive: &PasswordArchive) -> Result<()>;
}

/// File-backed store encrypting every file with AES-256-GCM (§10.4, §14).
/// The 32-octet key SHOULD come from the OS credential store.
pub struct EncryptedFileStore {
    dir: PathBuf,
    key: Zeroizing<[u8; 32]>,
}

impl EncryptedFileStore {
    pub fn new(dir: impl AsRef<Path>, key: [u8; 32]) -> Result<Self> {
        std::fs::create_dir_all(dir.as_ref())?;
        Ok(Self {
            dir: dir.as_ref().to_path_buf(),
            key: Zeroizing::new(key),
        })
    }

    fn cipher(&self) -> Result<Aes256Gcm> {
        Aes256Gcm::new_from_slice(&*self.key).map_err(|e| Error::Other(e.to_string()))
    }

    fn seal(&self, plain: &[u8]) -> Result<Vec<u8>> {
        let nonce_bytes: [u8; 12] = random_bytes(12).try_into().expect("12 bytes");
        let ct = self
            .cipher()?
            .encrypt(&Nonce::from(nonce_bytes), plain)
            .map_err(|_| Error::Other("state encryption failed".into()))?;
        let mut out = nonce_bytes.to_vec();
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn open(&self, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if data.len() < 12 {
            return Err(Error::Invalid("state file too short".into()));
        }
        let nonce: [u8; 12] = data[..12].try_into().expect("12 bytes");
        let pt = self
            .cipher()?
            .decrypt(&Nonce::from(nonce), &data[12..])
            .map_err(|_| Error::Invalid("state decryption failed".into()))?;
        Ok(Zeroizing::new(pt))
    }

    fn account_path(&self, user_id: &str) -> PathBuf {
        let name = hex::encode(Sha256::digest(user_id.as_bytes()));
        self.dir.join(format!("account-{name}.bin"))
    }

    fn write_atomic(&self, path: &Path, data: &[u8]) -> Result<()> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, data)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }
}

impl StateStore for EncryptedFileStore {
    fn load_all(&self) -> Result<Vec<PersistedAccount>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let p = entry?.path();
            let is_account = p
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("account-") && n.ends_with(".bin"));
            if is_account {
                let plain = self.open(&std::fs::read(&p)?)?;
                out.push(serde_json::from_slice(&plain)?);
            }
        }
        Ok(out)
    }

    fn save(&self, account: &PersistedAccount) -> Result<()> {
        let plain = Zeroizing::new(serde_json::to_vec(account)?);
        let sealed = self.seal(&plain)?;
        self.write_atomic(&self.account_path(&account.user_id), &sealed)
    }

    fn delete(&self, user_id: &str) -> Result<()> {
        match std::fs::remove_file(self.account_path(user_id)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }

    fn load_archive(&self) -> Result<PasswordArchive> {
        let p = self.dir.join("password-archive.bin");
        if !p.exists() {
            return Ok(PasswordArchive::default());
        }
        let plain = self.open(&std::fs::read(p)?)?;
        Ok(serde_json::from_slice(&plain)?)
    }

    fn save_archive(&self, archive: &PasswordArchive) -> Result<()> {
        let plain = Zeroizing::new(serde_json::to_vec(archive)?);
        let sealed = self.seal(&plain)?;
        self.write_atomic(&self.dir.join("password-archive.bin"), &sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_password() {
        let gw = GatewayPassword::generate();
        let s = gw.display();
        assert_eq!(s.len(), 22);
        assert!(gw.verify(&s));
        assert!(!gw.verify("AAAAAAAAAAAAAAAAAAAAAA"));
    }

    #[test]
    fn client_auth() {
        let gw = GatewayPassword::generate();
        let addrs = vec![
            Address {
                id: "a".into(),
                email: "User@x.org".into(),
                status: 1,
                ..Default::default()
            },
            Address {
                id: "b".into(),
                email: "off@x.org".into(),
                status: 0,
                ..Default::default()
            },
        ];
        let pw = gw.display();
        assert_eq!(
            authenticate_client(&gw, &addrs, "user@x.org", &pw)
                .unwrap()
                .id,
            "a"
        );
        assert!(authenticate_client(&gw, &addrs, "user+t@x.org", &pw).is_none());
        assert!(authenticate_client(&gw, &addrs, "off@x.org", &pw).is_none());
    }

    #[test]
    fn store_roundtrip() {
        let dir = std::env::temp_dir().join(format!("peb-test-{}", crate::util::random_hex(6)));
        let store = EncryptedFileStore::new(&dir, [9u8; 32]).unwrap();
        let gw = GatewayPassword::generate();
        let mut acc = PersistedAccount::new("u1", "user", "u@x.org", &gw);
        acc.last_event_id = Some("ev".into());
        store.save(&acc).unwrap();
        let all = store.load_all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].last_event_id.as_deref(), Some("ev"));
        let mut arch = store.load_archive().unwrap();
        let g2 = arch.get_or_generate("U@x.org");
        store.save_archive(&arch).unwrap();
        let mut arch2 = store.load_archive().unwrap();
        assert_eq!(arch2.get_or_generate("u@x.org").as_bytes(), g2.as_bytes());
        std::fs::remove_dir_all(dir).ok();
    }
}
