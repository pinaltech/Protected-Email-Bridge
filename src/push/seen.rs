//! Suppression of redelivered notifications across restarts.
//!
//! A Push Provider may deliver a message again after the application
//! restarts (`fcm_receiver_rs` acknowledges received messages only at its
//! next login, and keeps its list of seen messages in memory). Each
//! notification is encrypted with a fresh session key, so two distinct
//! notifications never share a ciphertext: a hash of `encryptedMessage`
//! identifies a delivery independently of the transport.
//!
//! Only hashes and expiry times are stored, never content.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;

use super::device_key::SecureStore;
use super::envelope::PushEnvelope;
use crate::error::Result;
use crate::util::now_unix;

/// The store entry holding the seen hashes.
pub const SEEN_ENTRY: &str = "push-seen-notifications";
/// How long a hash is remembered: the longest time a Push Provider keeps
/// an undelivered message (28 days for cloud messaging).
pub const SEEN_TTL: Duration = Duration::from_secs(28 * 24 * 3600);
/// Upper bound on remembered hashes; the oldest are forgotten first.
pub const SEEN_CAP: usize = 512;

#[derive(Default, Serialize, Deserialize)]
struct Stored {
    /// `(hash, expires_at_unix)`, oldest first.
    entries: Vec<(String, i64)>,
}

/// The hashes of processed notifications, persisted in a [`SecureStore`].
pub struct SeenNotifications {
    store: Arc<dyn SecureStore>,
    cache: Mutex<Option<Stored>>,
}

fn key(env: &PushEnvelope) -> String {
    hex::encode(&Sha256::digest(env.encrypted_message.as_bytes())[..16])
}

impl SeenNotifications {
    pub fn new(store: Arc<dyn SecureStore>) -> Self {
        Self {
            store,
            cache: Mutex::new(None),
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut Stored) -> R) -> R {
        let mut guard = self.cache.lock().expect("seen lock");
        let stored = guard.get_or_insert_with(|| match self.store.get(SEEN_ENTRY) {
            Ok(Some(v)) => serde_json::from_str(&v).unwrap_or_else(|_| {
                warn!("seen-notification list is unreadable; starting empty");
                Stored::default()
            }),
            Ok(None) => Stored::default(),
            Err(e) => {
                warn!("could not read the seen-notification list: {e}");
                Stored::default()
            }
        });
        f(stored)
    }

    /// Whether this delivery was already processed (and not yet expired).
    pub fn contains(&self, env: &PushEnvelope) -> bool {
        let k = key(env);
        let now = now_unix();
        self.with(|s| s.entries.iter().any(|(h, exp)| *h == k && *exp > now))
    }

    /// Remember a processed delivery and persist the list.
    pub fn insert(&self, env: &PushEnvelope) -> Result<()> {
        let k = key(env);
        let now = now_unix();
        let json = self.with(|s| {
            s.entries.retain(|(h, exp)| *exp > now && *h != k);
            s.entries.push((k, now + SEEN_TTL.as_secs() as i64));
            let excess = s.entries.len().saturating_sub(SEEN_CAP);
            s.entries.drain(..excess);
            serde_json::to_string(s)
        })?;
        self.store.put(SEEN_ENTRY, &json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::push::device_key::MemorySecureStore;

    fn env(m: &str) -> PushEnvelope {
        PushEnvelope {
            uid: "u".into(),
            encrypted_message: m.into(),
        }
    }

    #[test]
    fn remembers_across_instances() {
        let store = Arc::new(MemorySecureStore::default());
        let a = SeenNotifications::new(store.clone());
        assert!(!a.contains(&env("x")));
        a.insert(&env("x")).unwrap();
        assert!(a.contains(&env("x")));
        assert!(!a.contains(&env("y")));
        // A "restart": a new instance over the same store.
        let b = SeenNotifications::new(store.clone());
        assert!(b.contains(&env("x")));
        // Nothing but hashes is stored.
        assert!(!store.get(SEEN_ENTRY).unwrap().unwrap().contains("\"x\""));
    }

    #[test]
    fn expiry_and_cap() {
        let store = Arc::new(MemorySecureStore::default());
        store
            .put(
                SEEN_ENTRY,
                &format!(r#"{{"entries":[["{}",1]]}}"#, key(&env("old"))),
            )
            .unwrap();
        let s = SeenNotifications::new(store.clone());
        assert!(!s.contains(&env("old")), "expired");
        for i in 0..SEEN_CAP + 10 {
            s.insert(&env(&i.to_string())).unwrap();
        }
        assert!(!s.contains(&env("0")), "oldest forgotten");
        assert!(s.contains(&env(&(SEEN_CAP + 9).to_string())));
        let n: Stored = serde_json::from_str(&store.get(SEEN_ENTRY).unwrap().unwrap()).unwrap();
        assert_eq!(n.entries.len(), SEEN_CAP);
    }

    #[test]
    fn unreadable_list_starts_empty() {
        let store = Arc::new(MemorySecureStore::default());
        store.put(SEEN_ENTRY, "garbage").unwrap();
        let s = SeenNotifications::new(store);
        assert!(!s.contains(&env("x")));
        s.insert(&env("x")).unwrap();
        assert!(s.contains(&env("x")));
    }
}
