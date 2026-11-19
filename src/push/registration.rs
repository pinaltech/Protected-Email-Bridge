//! Device registration (§14.3): environment codes, the platform's
//! registration record, and the long-lived registration process.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use super::device_key::DeviceKeyManager;
use crate::api::ApiClient;
use crate::api::push::{DeviceRegistrationRequest, is_missing_scopes};
use crate::error::{Error, Result};
use crate::gateway::Gateway;

/// Extra delay after connectivity returns, before retrying (§14.3.3).
pub const NETWORK_RETRY_DELAY: Duration = Duration::from_millis(500);

/// Push Provider / build channel (§14.3.4, Appendix C.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "i64", into = "i64")]
pub enum Environment {
    /// 4 — Android cloud messaging (the reference profile).
    AndroidCloudMessaging,
    /// 6 — Apple push, production.
    AppleProduction,
    /// 7 — Apple push, beta / pre-release.
    AppleBeta,
    /// 14 — Apple push, production, alternate app target.
    AppleProductionAlternate,
    /// 15 — Apple push, development, alternate app target.
    AppleDevelopmentAlternate,
    /// 16 — Apple push, development.
    AppleDevelopment,
}

impl Environment {
    pub fn code(self) -> i64 {
        match self {
            Environment::AndroidCloudMessaging => 4,
            Environment::AppleProduction => 6,
            Environment::AppleBeta => 7,
            Environment::AppleProductionAlternate => 14,
            Environment::AppleDevelopmentAlternate => 15,
            Environment::AppleDevelopment => 16,
        }
    }
}

impl TryFrom<i64> for Environment {
    type Error = Error;

    /// Values outside the table are rejected as out of range.
    fn try_from(v: i64) -> Result<Self> {
        Ok(match v {
            4 => Environment::AndroidCloudMessaging,
            6 => Environment::AppleProduction,
            7 => Environment::AppleBeta,
            14 => Environment::AppleProductionAlternate,
            15 => Environment::AppleDevelopmentAlternate,
            16 => Environment::AppleDevelopment,
            other => {
                return Err(Error::Invalid(format!(
                    "push environment {other} is out of range"
                )));
            }
        })
    }
}

impl From<Environment> for i64 {
    fn from(e: Environment) -> i64 {
        e.code()
    }
}

/// The platform-supplied device registration record (§14.3.1).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRegistrationRecord {
    pub device_token: String,
    pub environment: Environment,
    /// Opaque; passed through unchanged.
    pub ping_notification_status: Option<i64>,
    /// Opaque; passed through unchanged.
    pub push_notification_status: Option<i64>,
}

impl std::fmt::Debug for DeviceRegistrationRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceRegistrationRecord")
            .field("environment", &self.environment)
            .field("ping_notification_status", &self.ping_notification_status)
            .field("push_notification_status", &self.push_notification_status)
            .finish_non_exhaustive()
    }
}

impl DeviceRegistrationRecord {
    pub fn new(device_token: impl Into<String>, environment: Environment) -> Self {
        Self {
            device_token: device_token.into(),
            environment,
            ping_notification_status: None,
            push_notification_status: None,
        }
    }

    /// The request body for this record and a device public key (§14.3.2).
    pub fn request(&self, public_key: String) -> DeviceRegistrationRequest {
        DeviceRegistrationRequest {
            device_token: self.device_token.clone(),
            environment: self.environment.code(),
            public_key,
            ping_notification_status: self.ping_notification_status,
            push_notification_status: self.push_notification_status,
        }
    }
}

/// A stored session, as seen by the registration process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSession {
    pub uid: String,
    pub user_id: String,
    /// Login, second factor and key unlock are all complete.
    pub fully_signed_in: bool,
}

/// The in-memory context available for a stored session.
pub enum SessionContext {
    /// The client to register the session with.
    Ready(ApiClient),
    /// Another in-memory user context still owns the Account (the session
    /// was rotated while the old context is alive).
    OwnedByOtherContext,
}

/// The stored sessions and their change notifications (§14.3.3 step 1b).
pub trait SessionProvider: Send + Sync {
    fn stored_sessions(&self) -> Result<Vec<StoredSession>>;
    /// `None` if the session has no usable context right now (skipped
    /// silently and picked up on a later trigger).
    fn context(&self, session: &StoredSession) -> Option<SessionContext>;
    /// Changes whenever the set of stored sessions changes.
    fn subscribe(&self) -> watch::Receiver<u64>;
}

/// The operating system's connectivity reports.
pub trait Connectivity: Send + Sync {
    fn is_online(&self) -> bool;
    /// Resolves once connectivity is reported.
    fn wait_online(&self) -> BoxFuture<'_, ()>;
}

/// [`Connectivity`] derived from API reachability (§4.8): the client's
/// connectivity state, probed with `GET /tests/ping` while it is down.
pub struct ApiConnectivity {
    client: ApiClient,
    probe_interval: Duration,
}

impl ApiConnectivity {
    pub fn new(client: ApiClient) -> Self {
        Self {
            client,
            probe_interval: Duration::from_secs(5),
        }
    }
}

impl Connectivity for ApiConnectivity {
    fn is_online(&self) -> bool {
        self.client.is_connected()
    }

    fn wait_online(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            while !self.client.ping().await {
                tokio::time::sleep(self.probe_interval).await;
            }
        })
    }
}

/// Receives registration-step failures (§14.3.3 step 5).
pub trait RegistrationObserver: Send + Sync {
    fn registration_failed(&self, _error: &Error) {}
    fn registered(&self, _session_uid: &str) {}
}

struct LogObserver;
impl RegistrationObserver for LogObserver {
    fn registration_failed(&self, error: &Error) {
        warn!("push device registration failed: {error}");
    }
}

/// Outcome of one registration step.
#[derive(Debug)]
pub enum StepOutcome {
    /// Every candidate was registered, or there was nothing to do.
    Done,
    /// A session lacks scopes (403 / 9100); abandoned without error.
    Deferred,
    /// No HTTP response: retry the whole step once online.
    NetworkFailure,
    /// Fatal for the step; reported.
    Failed(Error),
}

fn is_network(e: &Error) -> bool {
    match e {
        Error::Network(_) => true,
        Error::Io(io) => io.kind() == std::io::ErrorKind::UnexpectedEof,
        _ => false,
    }
}

/// The background registration process (§14.3.3). Its state — the current
/// record and the registered-session set — lives in memory only, so every
/// process start re-registers every signed-in session.
pub struct Registrar {
    sessions: Arc<dyn SessionProvider>,
    keys: Arc<DeviceKeyManager>,
    connectivity: Arc<dyn Connectivity>,
    records: watch::Receiver<Option<DeviceRegistrationRecord>>,
    observer: Arc<dyn RegistrationObserver>,
}

impl Registrar {
    pub fn new(
        sessions: Arc<dyn SessionProvider>,
        keys: Arc<DeviceKeyManager>,
        connectivity: Arc<dyn Connectivity>,
        records: watch::Receiver<Option<DeviceRegistrationRecord>>,
        observer: Option<Arc<dyn RegistrationObserver>>,
    ) -> Self {
        Self {
            sessions,
            keys,
            connectivity,
            records,
            observer: observer.unwrap_or_else(|| Arc::new(LogObserver)),
        }
    }

    pub fn spawn(self) -> JoinHandle<()> {
        tokio::spawn(self.run())
    }

    /// Run until the record sender or the session provider goes away.
    pub async fn run(mut self) {
        let mut session_changes = self.sessions.subscribe();
        let mut record = self.records.borrow_and_update().clone();
        let mut registered: HashSet<String> = HashSet::new();
        loop {
            // One step, repeated while the network is failing.
            loop {
                match self.step(record.as_ref(), &mut registered).await {
                    StepOutcome::NetworkFailure => {
                        let connectivity = self.connectivity.clone();
                        let wait = async move {
                            connectivity.wait_online().await;
                            tokio::time::sleep(NETWORK_RETRY_DELAY).await;
                        };
                        tokio::select! {
                            _ = wait => {}
                            r = self.records.changed() => {
                                if r.is_err() { return; }
                                Self::take_record(&mut self.records, &mut record, &mut registered);
                            }
                            s = session_changes.changed() => {
                                if s.is_err() { return; }
                            }
                        }
                    }
                    StepOutcome::Failed(e) => {
                        self.observer.registration_failed(&e);
                        break;
                    }
                    StepOutcome::Deferred => {
                        debug!("push registration deferred until session scopes change");
                        break;
                    }
                    StepOutcome::Done => break,
                }
            }
            tokio::select! {
                r = self.records.changed() => {
                    if r.is_err() { return; }
                    Self::take_record(&mut self.records, &mut record, &mut registered);
                }
                s = session_changes.changed() => {
                    if s.is_err() { return; }
                }
            }
        }
    }

    /// Trigger 1a: a new or changed record clears the registered set.
    fn take_record(
        rx: &mut watch::Receiver<Option<DeviceRegistrationRecord>>,
        current: &mut Option<DeviceRegistrationRecord>,
        registered: &mut HashSet<String>,
    ) {
        let new = rx.borrow_and_update().clone();
        if new != *current {
            *current = new;
            registered.clear();
        }
    }

    /// One registration step (§14.3.3 steps 2–5).
    pub async fn step(
        &self,
        record: Option<&DeviceRegistrationRecord>,
        registered: &mut HashSet<String>,
    ) -> StepOutcome {
        let Some(record) = record else {
            return StepOutcome::Done;
        };
        let sessions = match self.sessions.stored_sessions() {
            Ok(s) => s,
            Err(e) => return StepOutcome::Failed(e),
        };
        let candidates: Vec<StoredSession> = sessions
            .into_iter()
            .filter(|s| s.fully_signed_in && !s.uid.is_empty() && !registered.contains(&s.uid))
            .collect();
        for candidate in candidates {
            let client = match self.sessions.context(&candidate) {
                None => continue,
                Some(SessionContext::OwnedByOtherContext) => {
                    warn!(
                        user = %candidate.user_id,
                        "another context owns this account; skipping push registration"
                    );
                    continue;
                }
                Some(SessionContext::Ready(c)) => c,
            };
            let public_key = match self
                .keys
                .get_or_create()
                .and_then(|k| k.armored_public_key())
            {
                Ok(pk) => pk,
                Err(e) => return StepOutcome::Failed(e),
            };
            match client.register_device(&record.request(public_key)).await {
                Ok(()) => {
                    self.observer.registered(&candidate.uid);
                    registered.insert(candidate.uid);
                }
                Err(e) if is_network(&e) => return StepOutcome::NetworkFailure,
                Err(e) if is_missing_scopes(&e) => return StepOutcome::Deferred,
                Err(e) => return StepOutcome::Failed(e),
            }
        }
        StepOutcome::Done
    }
}

/// The Gateway's stored sessions are those of its persisted, signed-in
/// accounts. An account is fully signed in once its context (with unlocked
/// keys) is live.
impl SessionProvider for Gateway {
    fn stored_sessions(&self) -> Result<Vec<StoredSession>> {
        let live = self.accounts();
        Ok(self
            .store
            .load_all()?
            .into_iter()
            .filter(|p| p.is_signed_in())
            .map(|p| StoredSession {
                fully_signed_in: live.iter().any(|a| a.user_id() == p.user_id),
                uid: p.session_uid,
                user_id: p.user_id,
            })
            .collect())
    }

    fn context(&self, session: &StoredSession) -> Option<SessionContext> {
        let ctx = self
            .accounts()
            .into_iter()
            .find(|a| a.user_id() == session.user_id)?;
        if ctx.persisted().session_uid == session.uid {
            Some(SessionContext::Ready(ctx.client.clone()))
        } else {
            Some(SessionContext::OwnedByOtherContext)
        }
    }

    fn subscribe(&self) -> watch::Receiver<u64> {
        self.subscribe_sessions()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::push::device_key::MemorySecureStore;
    use crate::push::test_support;

    struct FakeSessions {
        sessions: Vec<(StoredSession, Option<bool>)>,
        client: ApiClient,
        tx: watch::Sender<u64>,
    }

    impl SessionProvider for FakeSessions {
        fn stored_sessions(&self) -> Result<Vec<StoredSession>> {
            Ok(self.sessions.iter().map(|(s, _)| s.clone()).collect())
        }
        fn context(&self, s: &StoredSession) -> Option<SessionContext> {
            let (_, owned) = self.sessions.iter().find(|(x, _)| x.uid == s.uid)?;
            match owned {
                None => None,
                Some(true) => Some(SessionContext::Ready(self.client.clone())),
                Some(false) => Some(SessionContext::OwnedByOtherContext),
            }
        }
        fn subscribe(&self) -> watch::Receiver<u64> {
            self.tx.subscribe()
        }
    }

    struct Online;
    impl Connectivity for Online {
        fn is_online(&self) -> bool {
            true
        }
        fn wait_online(&self) -> BoxFuture<'_, ()> {
            Box::pin(async {})
        }
    }

    fn session(uid: &str, fully: bool) -> StoredSession {
        StoredSession {
            uid: uid.into(),
            user_id: format!("user-{uid}"),
            fully_signed_in: fully,
        }
    }

    async fn registrar(
        base: &str,
        sessions: Vec<(StoredSession, Option<bool>)>,
    ) -> (Registrar, Arc<DeviceKeyManager>) {
        let keys = Arc::new(DeviceKeyManager::new(
            Arc::new(MemorySecureStore::default()),
        ));
        let fake = FakeSessions {
            sessions,
            client: test_support::client(base).await,
            tx: watch::channel(0).0,
        };
        let (_tx, rx) = watch::channel(None);
        let r = Registrar::new(Arc::new(fake), keys.clone(), Arc::new(Online), rx, None);
        (r, keys)
    }

    #[tokio::test]
    async fn step_registers_only_ready_unregistered_sessions() {
        let stub = test_support::start(Arc::new(|_| (200, r#"{"Code":1000}"#.into()))).await;
        let (r, keys) = registrar(
            &stub.base,
            vec![
                (session("a", true), Some(true)),
                (session("b", false), Some(true)), // mid-login: skipped
                (session("c", true), Some(false)), // owned by another context
                (session("d", true), None),        // no context yet
                (session("e", true), Some(true)),
            ],
        )
        .await;
        let mut done = HashSet::new();
        assert!(matches!(r.step(None, &mut done).await, StepOutcome::Done));
        assert!(stub.seen.lock().unwrap().is_empty());

        let mut rec = DeviceRegistrationRecord::new("tok", Environment::AndroidCloudMessaging);
        rec.push_notification_status = Some(1);
        assert!(matches!(
            r.step(Some(&rec), &mut done).await,
            StepOutcome::Done
        ));
        assert_eq!(done, HashSet::from(["a".to_string(), "e".to_string()]));
        let seen = stub.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].method, "POST");
        assert_eq!(seen[0].path, "/core/v4/devices");
        assert_eq!(seen[0].body["DeviceToken"], "tok");
        assert_eq!(seen[0].body["Environment"], 4);
        assert!(seen[0].body["PingNotificationStatus"].is_null());
        assert_eq!(seen[0].body["PushNotificationStatus"], 1);
        let pk = keys.load().unwrap().unwrap().armored_public_key().unwrap();
        assert_eq!(seen[0].body["PublicKey"], pk.as_str());
        assert_eq!(seen[1].body["PublicKey"], pk.as_str());

        // Already registered: nothing more is sent.
        assert!(matches!(
            r.step(Some(&rec), &mut done).await,
            StepOutcome::Done
        ));
        assert_eq!(stub.seen.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn missing_scopes_defer_and_other_errors_fail() {
        let stub = test_support::start(Arc::new(|_| {
            (403, r#"{"Code":9100,"Error":"missing scopes"}"#.into())
        }))
        .await;
        let (r, _) = registrar(&stub.base, vec![(session("a", true), Some(true))]).await;
        let rec = DeviceRegistrationRecord::new("tok", Environment::AppleProduction);
        let mut done = HashSet::new();
        assert!(matches!(
            r.step(Some(&rec), &mut done).await,
            StepOutcome::Deferred
        ));
        assert!(done.is_empty());

        let stub =
            test_support::start(Arc::new(|_| (422, r#"{"Code":2001,"Error":"bad"}"#.into()))).await;
        let (r, _) = registrar(&stub.base, vec![(session("a", true), Some(true))]).await;
        assert!(matches!(
            r.step(Some(&rec), &mut done).await,
            StepOutcome::Failed(_)
        ));
    }

    #[tokio::test]
    async fn unreachable_service_is_a_network_failure() {
        // Bind and drop to get a port nobody listens on.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let (r, _) = registrar(
            &format!("http://127.0.0.1:{port}"),
            vec![(session("a", true), Some(true))],
        )
        .await;
        let rec = DeviceRegistrationRecord::new("tok", Environment::AndroidCloudMessaging);
        let mut done = HashSet::new();
        assert!(matches!(
            r.step(Some(&rec), &mut done).await,
            StepOutcome::NetworkFailure
        ));
    }

    #[tokio::test]
    async fn run_reregisters_after_record_change() {
        let stub = test_support::start(Arc::new(|_| (200, r#"{"Code":1000}"#.into()))).await;
        let keys = Arc::new(DeviceKeyManager::new(
            Arc::new(MemorySecureStore::default()),
        ));
        let (stx, _) = watch::channel(0u64);
        let fake = Arc::new(FakeSessions {
            sessions: vec![(session("a", true), Some(true))],
            client: test_support::client(&stub.base).await,
            tx: stx,
        });
        let (rtx, rrx) = watch::channel(None);
        let registered = Arc::new(Mutex::new(Vec::new()));
        struct Obs(Arc<Mutex<Vec<String>>>);
        impl RegistrationObserver for Obs {
            fn registered(&self, uid: &str) {
                self.0.lock().unwrap().push(uid.to_string());
            }
        }
        let h = Registrar::new(
            fake.clone(),
            keys,
            Arc::new(Online),
            rrx,
            Some(Arc::new(Obs(registered.clone()))),
        )
        .spawn();
        rtx.send_replace(Some(DeviceRegistrationRecord::new(
            "t1",
            Environment::AndroidCloudMessaging,
        )));
        let wait_for = |n: usize| {
            let registered = registered.clone();
            async move {
                for _ in 0..200 {
                    if registered.lock().unwrap().len() >= n {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                panic!("not registered {n} times");
            }
        };
        wait_for(1).await;
        // A session-set change alone does not re-register.
        fake.tx.send_replace(1);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(registered.lock().unwrap().len(), 1);
        // A new token clears the registered set.
        rtx.send_replace(Some(DeviceRegistrationRecord::new(
            "t2",
            Environment::AndroidCloudMessaging,
        )));
        wait_for(2).await;
        let seen = stub.seen.lock().unwrap().clone();
        assert_eq!(seen.last().unwrap().body["DeviceToken"], "t2");
        h.abort();
    }

    #[test]
    fn environment_codes() {
        for c in [4, 6, 7, 14, 15, 16] {
            assert_eq!(Environment::try_from(c).unwrap().code(), c);
        }
        for c in [0, 1, 5, 8, 13, 17, -4] {
            assert!(Environment::try_from(c).is_err());
        }
        let r: DeviceRegistrationRecord = serde_json::from_str(
            r#"{"device_token":"t","environment":4,"ping_notification_status":null,"push_notification_status":2}"#,
        )
        .unwrap();
        assert_eq!(r.environment, Environment::AndroidCloudMessaging);
        assert!(
            serde_json::from_str::<DeviceRegistrationRecord>(
                r#"{"device_token":"t","environment":5,"ping_notification_status":null,"push_notification_status":null}"#
            )
            .is_err()
        );
    }
}
