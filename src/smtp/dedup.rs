//! Duplicate suppression of submissions (§13.6) and SMTP failure
//! throttling (§13.16).

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::config::limits;

/// Dedup key: (fingerprint, order-independent recipient set).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DedupKey {
    pub fingerprint: String,
    pub recipients: BTreeSet<String>,
}

impl DedupKey {
    pub fn new(fingerprint: String, recipients: impl IntoIterator<Item = String>) -> Self {
        Self {
            fingerprint,
            recipients: recipients
                .into_iter()
                .map(|r| r.trim().to_lowercase())
                .filter(|r| !r.is_empty())
                .collect(),
        }
    }
}

/// State of an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DedupState {
    InFlight,
    /// Sent; carries the resulting Service message ID.
    Sent(String),
    /// Failed (entry removed).
    Removed,
}

struct Entry {
    inserted: Instant,
    state: watch::Sender<DedupState>,
}

/// Outcome of [`SendDedup::begin`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Begin {
    /// No identical submission: an entry was inserted, proceed with sending.
    Proceed,
    /// An identical submission already succeeded: report success.
    AlreadySent(String),
}

/// In-memory dedup table; entries expire 30 minutes after insertion.
#[derive(Default)]
pub struct SendDedup {
    entries: Mutex<HashMap<DedupKey, Entry>>,
}

impl SendDedup {
    pub fn new() -> Self {
        Self::default()
    }

    fn prune(map: &mut HashMap<DedupKey, Entry>) {
        map.retain(|_, e| e.inserted.elapsed() < limits::SEND_DEDUP_LIFETIME);
    }

    fn watch(&self, key: &DedupKey) -> Option<watch::Receiver<DedupState>> {
        let mut m = self.entries.lock().expect("dedup lock");
        Self::prune(&mut m);
        m.get(key).map(|e| e.state.subscribe())
    }

    async fn wait_resolved(mut rx: watch::Receiver<DedupState>, timeout: Duration) -> DedupState {
        let fut = async {
            loop {
                let s = rx.borrow().clone();
                if s != DedupState::InFlight {
                    return s;
                }
                if rx.changed().await.is_err() {
                    return DedupState::Removed;
                }
            }
        };
        tokio::time::timeout(timeout, fut)
            .await
            .unwrap_or(DedupState::InFlight)
    }

    /// SMTP path: wait up to 90 s for an identical entry to resolve, then
    /// either report it as sent or insert a new in-flight entry.
    pub async fn begin(&self, key: &DedupKey) -> Begin {
        loop {
            if let Some(rx) = self.watch(key) {
                match Self::wait_resolved(rx, limits::SEND_DEDUP_WAIT).await {
                    DedupState::Sent(id) => return Begin::AlreadySent(id),
                    DedupState::InFlight => {
                        // Still unresolved after the wait: proceed anyway.
                    }
                    DedupState::Removed => {}
                }
            }
            let mut m = self.entries.lock().expect("dedup lock");
            match m.get(key) {
                Some(e) if *e.state.borrow() == DedupState::InFlight => {
                    // Someone else inserted meanwhile; replace after timeout.
                    if e.inserted.elapsed() < limits::SEND_DEDUP_WAIT {
                        drop(m);
                        continue;
                    }
                }
                Some(e) => {
                    if let DedupState::Sent(id) = &*e.state.borrow() {
                        return Begin::AlreadySent(id.clone());
                    }
                }
                None => {}
            }
            let (tx, _) = watch::channel(DedupState::InFlight);
            m.insert(
                key.clone(),
                Entry {
                    inserted: Instant::now(),
                    state: tx,
                },
            );
            return Begin::Proceed;
        }
    }

    /// Mark the entry as sent.
    pub fn mark_sent(&self, key: &DedupKey, message_id: &str) {
        if let Some(e) = self.entries.lock().expect("dedup lock").get(key) {
            e.state
                .send_replace(DedupState::Sent(message_id.to_string()));
        }
    }

    /// Remove the entry after a failure.
    pub fn remove(&self, key: &DedupKey) {
        if let Some(e) = self.entries.lock().expect("dedup lock").remove(key) {
            e.state.send_replace(DedupState::Removed);
        }
    }

    /// IMAP APPEND path (§11.10.4 step 4): only query. Waits up to 90 s for
    /// an in-flight entry; returns the sent message ID on success.
    pub async fn query(&self, key: &DedupKey) -> Option<String> {
        let rx = self.watch(key)?;
        match Self::wait_resolved(rx, limits::SEND_DEDUP_WAIT).await {
            DedupState::Sent(id) => Some(id),
            _ => None,
        }
    }
}

/// Per-account SMTP failure throttle (§13.16).
#[derive(Debug, Default)]
pub struct FailureThrottle {
    counter: u32,
    prev: Option<Instant>,
}

impl FailureThrottle {
    /// Check before a submission. Returns false if it must be rejected.
    pub fn check(&mut self, now: Instant) -> bool {
        if self.counter >= limits::SMTP_FAILURE_THRESHOLD {
            match self.prev {
                Some(p) if now.duration_since(p) < limits::SMTP_FAILURE_LOCKOUT => return false,
                _ => self.counter = 0,
            }
        }
        true
    }

    /// Record the outcome of a submission requested at `t`.
    pub fn record(&mut self, t: Instant, failed: bool) {
        let close = self
            .prev
            .is_some_and(|p| t.saturating_duration_since(p) <= limits::SMTP_FAILURE_WINDOW);
        if failed && close {
            self.counter += 1;
        } else {
            self.counter = 0;
        }
        self.prev = Some(t);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dedup_flow() {
        let d = SendDedup::new();
        let k = DedupKey::new("fp".into(), vec!["B@x".into(), "a@x".into()]);
        let k2 = DedupKey::new("fp".into(), vec!["a@x".into(), "b@x".into()]);
        assert_eq!(k, k2);
        assert_eq!(d.begin(&k).await, Begin::Proceed);
        d.mark_sent(&k, "m1");
        assert_eq!(d.begin(&k2).await, Begin::AlreadySent("m1".into()));
        assert_eq!(d.query(&k).await, Some("m1".into()));
        d.remove(&k);
        assert_eq!(d.query(&k).await, None);
    }

    #[test]
    fn throttle() {
        let mut t = FailureThrottle::default();
        let t0 = Instant::now();
        for i in 0..4 {
            let ti = t0 + Duration::from_millis(100 * i);
            assert!(t.check(ti));
            t.record(ti, true);
        }
        assert!(!t.check(t0 + Duration::from_secs(5)));
        assert!(t.check(t0 + Duration::from_secs(25)));
    }
}
