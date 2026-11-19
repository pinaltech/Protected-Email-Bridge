//! The push envelope (§14.4.1) and client-side decryption (§14.4.3).

use super::device_key::DeviceKeyManager;
use super::payload::Notification;
use crate::error::{Error, Result};

/// Envelope field carrying the session UID (case-sensitive).
pub const FIELD_UID: &str = "UID";
/// Envelope field carrying the armored OpenPGP message (case-sensitive).
pub const FIELD_ENCRYPTED_MESSAGE: &str = "encryptedMessage";

/// The data message delivered by the Push Provider.
#[derive(Clone, PartialEq, Eq)]
pub struct PushEnvelope {
    /// The recipient Account's registered session UID (not the UserID).
    pub uid: String,
    /// Armored OpenPGP message encrypted to the device key.
    pub encrypted_message: String,
}

impl std::fmt::Debug for PushEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushEnvelope")
            .field("uid", &self.uid)
            .field("encrypted_len", &self.encrypted_message.len())
            .finish()
    }
}

impl PushEnvelope {
    /// Build an envelope from the data message's key/value pairs. Both
    /// fields are required; names are matched case-sensitively.
    pub fn from_fields<'a>(fields: impl IntoIterator<Item = (&'a str, &'a str)>) -> Option<Self> {
        let mut uid = None;
        let mut enc = None;
        for (k, v) in fields {
            match k {
                FIELD_UID => uid = Some(v.to_string()),
                FIELD_ENCRYPTED_MESSAGE => enc = Some(v.to_string()),
                _ => {}
            }
        }
        match (uid, enc) {
            (Some(uid), Some(encrypted_message)) if !uid.is_empty() => Some(Self {
                uid,
                encrypted_message,
            }),
            _ => None,
        }
    }

    /// Build an envelope from a JSON object holding the fields either at the
    /// top level or under `"data"` (the shape of a decrypted web-push
    /// payload).
    pub fn from_json(v: &serde_json::Value) -> Option<Self> {
        let obj = v
            .get("data")
            .filter(|d| d.is_object())
            .unwrap_or(v)
            .as_object()?;
        Self::from_fields(
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.as_str(), s))),
        )
    }

    /// Steps 1–4 and 6 of §14.4.3: load the device key (never generating
    /// one), decrypt without signature verification, and parse the
    /// notification. Needs neither network access nor unlocked mailbox keys.
    pub fn open(&self, keys: &DeviceKeyManager) -> Result<Notification> {
        let key = keys
            .load()?
            .ok_or_else(|| Error::Crypto("no device key is stored".into()))?;
        let plain = key.decrypt(&self.encrypted_message)?;
        Notification::parse(&plain)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::push::device_key::tests::service_encrypt;
    use crate::push::device_key::{DEVICE_KEY_ENTRY, MemorySecureStore, SecureStore};

    #[test]
    fn fields_are_case_sensitive_and_required() {
        assert!(PushEnvelope::from_fields([("uid", "u"), ("encryptedMessage", "x")]).is_none());
        assert!(PushEnvelope::from_fields([("UID", "u")]).is_none());
        let e = PushEnvelope::from_fields([("UID", "u"), ("encryptedMessage", "x"), ("o", "1")])
            .unwrap();
        assert_eq!(e.uid, "u");
        let j = serde_json::json!({"data": {"UID": "u", "encryptedMessage": "x"}});
        assert_eq!(PushEnvelope::from_json(&j), Some(e));
    }

    #[test]
    fn open_decrypts_and_parses() {
        let store = Arc::new(MemorySecureStore::default());
        let keys = DeviceKeyManager::new(store.clone());
        let env = |plain: &str| PushEnvelope {
            uid: "u".into(),
            encrypted_message: service_encrypt(
                &keys.get_or_create().unwrap().armored_public_key().unwrap(),
                plain.as_bytes(),
            ),
        };
        let ok = env(
            r#"{"type":"open_url","data":{"title":"","subtitle":"","body":"b","url":"https://x",
            "sender":{"Name":"","Address":"","Group":""},"badge":0,"largeIcon":"","smallIcon":"","messageId":""}}"#,
        );
        assert!(matches!(ok.open(&keys).unwrap(), Notification::OpenUrl(_)));

        let bad_json = env("{");
        assert!(matches!(bad_json.open(&keys), Err(Error::Json(_))));

        let unknown = env(r#"{"type":"nope","data":{}}"#);
        assert!(matches!(unknown.open(&keys), Err(Error::Json(_))));

        store.delete(DEVICE_KEY_ENTRY).unwrap();
        assert!(matches!(ok.open(&keys), Err(Error::Crypto(_))));
        // A regenerated key cannot read notifications for the old one.
        keys.get_or_create().unwrap();
        assert!(matches!(ok.open(&keys), Err(Error::Crypto(_))));
    }
}
