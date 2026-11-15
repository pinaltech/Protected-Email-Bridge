//! Connection admission control (§11.12) and the IMAP login throttle
//! (§11.4.1).

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::limits;

/// Mail client families recognised by their `ID name` (§11.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientKind {
    Outlook,
    Thunderbird,
    AppleMail,
    Unknown,
}

impl ClientKind {
    pub fn detect(id_name: &str) -> Self {
        let n = id_name.to_lowercase();
        if n.contains("outlook") {
            ClientKind::Outlook
        } else if n.contains("thunderbird") {
            ClientKind::Thunderbird
        } else if n.contains("mac") && n.contains("mail") {
            ClientKind::AppleMail
        } else {
            ClientKind::Unknown
        }
    }

    /// Concurrent session limit (`None` = unlimited).
    pub fn session_limit(self, fallback_profile: bool) -> Option<usize> {
        match self {
            ClientKind::AppleMail => Some(if fallback_profile {
                limits::APPLE_MAIL_SESSION_CAP_FALLBACK
            } else {
                limits::APPLE_MAIL_SESSION_CAP
            }),
            _ => None,
        }
    }
}

/// Rolling new-connection rate limiter: 6 buckets × 10 s, at most 400
/// connections per window.
pub struct ConnectionRateLimiter {
    inner: Mutex<VecDeque<(Instant, usize)>>,
    bucket: Duration,
    buckets: usize,
    cap: usize,
}

impl Default for ConnectionRateLimiter {
    fn default() -> Self {
        Self::new(
            limits::IMAP_CONNECTION_BUCKET,
            limits::IMAP_CONNECTION_WINDOW_BUCKETS,
            limits::IMAP_NEW_CONNECTION_CAP,
        )
    }
}

impl ConnectionRateLimiter {
    pub fn new(bucket: Duration, buckets: usize, cap: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::new()),
            bucket,
            buckets,
            cap,
        }
    }

    /// Record a new connection; returns false if it must be closed.
    pub fn admit(&self) -> bool {
        let now = Instant::now();
        let window = self.bucket * self.buckets as u32;
        let mut q = self.inner.lock().expect("rate limiter lock");
        while q
            .front()
            .is_some_and(|(t, _)| now.duration_since(*t) >= window)
        {
            q.pop_front();
        }
        let total: usize = q.iter().map(|(_, n)| n).sum();
        if total >= self.cap {
            return false;
        }
        match q.back_mut() {
            Some((t, n)) if now.duration_since(*t) < self.bucket => *n += 1,
            _ => q.push_back((now, 1)),
        }
        true
    }
}

/// Per-client concurrent session tracking.
#[derive(Default)]
pub struct SessionCounter {
    inner: Mutex<HashMap<ClientKind, usize>>,
    pub fallback_profile: bool,
}

impl SessionCounter {
    /// Register a session for a client; returns false if over the limit
    /// (the session must receive `* BYE Too many connections for this IMAP
    /// client`).
    pub fn register(&self, kind: ClientKind) -> bool {
        let mut m = self.inner.lock().expect("session counter lock");
        let n = m.entry(kind).or_default();
        if let Some(limit) = kind.session_limit(self.fallback_profile)
            && *n >= limit
        {
            return false;
        }
        *n += 1;
        true
    }

    pub fn unregister(&self, kind: ClientKind) {
        let mut m = self.inner.lock().expect("session counter lock");
        if let Some(n) = m.get_mut(&kind) {
            *n = n.saturating_sub(1);
        }
    }
}

/// Outcome of a failed login attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginFailure {
    Failed,
    /// The third consecutive failure: report "login blocked".
    Blocked,
}

/// Global login throttle: after 3 consecutive failures the third is
/// reported as blocked and the counter resets after the jail interval.
pub struct LoginThrottle {
    inner: Mutex<(u32, Option<Instant>)>,
    jail: Duration,
}

impl LoginThrottle {
    pub fn new(jail: Duration) -> Self {
        Self {
            inner: Mutex::new((0, None)),
            jail,
        }
    }

    /// Whether logins are currently jailed.
    pub fn is_jailed(&self) -> bool {
        let mut g = self.inner.lock().expect("throttle lock");
        if let Some(t) = g.1 {
            if t.elapsed() >= self.jail {
                *g = (0, None);
                return false;
            }
            return true;
        }
        false
    }

    pub fn record_failure(&self) -> LoginFailure {
        let mut g = self.inner.lock().expect("throttle lock");
        g.0 += 1;
        if g.0 >= limits::IMAP_LOGIN_FAILURES {
            g.0 = 0;
            if !self.jail.is_zero() {
                g.1 = Some(Instant::now());
            }
            LoginFailure::Blocked
        } else {
            LoginFailure::Failed
        }
    }

    pub fn record_success(&self) {
        *self.inner.lock().expect("throttle lock") = (0, None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect() {
        assert_eq!(ClientKind::detect("Microsoft Outlook"), ClientKind::Outlook);
        assert_eq!(ClientKind::detect("Mac OS X Mail"), ClientKind::AppleMail);
        assert_eq!(ClientKind::detect("Mac Notes"), ClientKind::Unknown);
    }

    #[test]
    fn rate() {
        let l = ConnectionRateLimiter::new(Duration::from_secs(10), 6, 3);
        assert!(l.admit() && l.admit() && l.admit());
        assert!(!l.admit());
    }

    #[test]
    fn apple_limit() {
        let c = SessionCounter::default();
        for _ in 0..60 {
            assert!(c.register(ClientKind::AppleMail));
        }
        assert!(!c.register(ClientKind::AppleMail));
        assert!(c.register(ClientKind::Thunderbird));
    }

    #[test]
    fn throttle() {
        let t = LoginThrottle::new(Duration::ZERO);
        assert_eq!(t.record_failure(), LoginFailure::Failed);
        assert_eq!(t.record_failure(), LoginFailure::Failed);
        assert_eq!(t.record_failure(), LoginFailure::Blocked);
        assert_eq!(t.record_failure(), LoginFailure::Failed);
    }
}
