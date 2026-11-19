//! Android cloud-messaging Push Provider transport (environment 4,
//! §14.3.4), built on [`fcm_receiver_rs`].
//!
//! The provider registers this installation with the cloud-messaging
//! service, reports the resulting device token as a
//! [`DeviceRegistrationRecord`], and forwards every received data message
//! carrying the `UID` / `encryptedMessage` fields (§14.4.1) as a
//! [`PushEnvelope`]. It never looks inside the encrypted message.
//!
//! `fcm_receiver_rs` is blocking, so the provider runs on its own OS thread
//! (outside the async runtime). Its credentials — Android ID, security
//! token, tokens and the web-push key pair — are secrets and live in the
//! [`SecureStore`] next to the device key.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use fcm_receiver_rs::client::{AndroidApp, FcmClient};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use super::device_key::SecureStore;
use super::envelope::PushEnvelope;
use super::registration::{DeviceRegistrationRecord, Environment};
use crate::api::backoff::Backoff;
use crate::error::{Error, Result};

/// The secure-store entry holding the provider credentials.
pub const FCM_CREDENTIALS_ENTRY: &str = "push-fcm-credentials";

/// Android package identity, for projects restricted to a package.
#[derive(Debug, Clone)]
pub struct FcmAndroidApp {
    pub gcm_sender_id: String,
    pub android_package: String,
    /// SHA-1 of the signing certificate, hex without separators.
    pub android_package_cert: String,
}

/// Operator-provided cloud-messaging project settings.
#[derive(Debug, Clone)]
pub struct FcmConfig {
    pub api_key: String,
    pub app_id: String,
    pub project_id: String,
    pub android_app: Option<FcmAndroidApp>,
    pub vapid_key: Option<String>,
    pub heartbeat_interval: Duration,
}

impl FcmConfig {
    pub fn new(
        api_key: impl Into<String>,
        app_id: impl Into<String>,
        project_id: impl Into<String>,
    ) -> Self {
        Self {
            api_key: api_key.into(),
            app_id: app_id.into(),
            project_id: project_id.into(),
            android_app: None,
            vapid_key: None,
            heartbeat_interval: Duration::from_secs(600),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct FcmCredentials {
    android_id: u64,
    security_token: u64,
    fcm_token: String,
    gcm_token: String,
    private_key_b64: String,
    auth_secret_b64: String,
}

impl Drop for FcmCredentials {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.private_key_b64.zeroize();
        self.auth_secret_b64.zeroize();
        self.security_token.zeroize();
    }
}

fn fcm_err(e: fcm_receiver_rs::Error) -> Error {
    use fcm_receiver_rs::Error as F;
    match e {
        F::Http(_) | F::Io(_) | F::Tls(_) => Error::Network(format!("cloud messaging: {e}")),
        other => Error::Other(format!("cloud messaging: {other}")),
    }
}

/// Callback receiving the device registration record.
pub type RecordSink = Arc<dyn Fn(DeviceRegistrationRecord) + Send + Sync>;

/// A running cloud-messaging receiver.
pub struct FcmPushProvider {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl FcmPushProvider {
    /// Start the receiver thread. It reconnects with the back-off of §4.6
    /// until [`Self::stop`] is called.
    pub fn start(
        config: FcmConfig,
        store: Arc<dyn SecureStore>,
        on_record: RecordSink,
        envelopes: mpsc::UnboundedSender<PushEnvelope>,
    ) -> Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let thread = std::thread::Builder::new()
            .name("fcm-receiver".into())
            .spawn(move || run(config, store, on_record, envelopes, stop2))?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }

    /// Ask the receiver to stop. The blocking socket read cannot be
    /// interrupted, so the thread exits once the current connection ends;
    /// no further envelopes are forwarded after this call.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    /// Delete the stored credentials so that the next start registers a new
    /// device token.
    pub fn forget_credentials(store: &dyn SecureStore) -> Result<()> {
        store.delete(FCM_CREDENTIALS_ENTRY)
    }
}

impl Drop for FcmPushProvider {
    fn drop(&mut self) {
        self.stop();
        // Detach: joining could block until the server closes the socket.
        drop(self.thread.take());
    }
}

fn run(
    config: FcmConfig,
    store: Arc<dyn SecureStore>,
    on_record: RecordSink,
    envelopes: mpsc::UnboundedSender<PushEnvelope>,
    stop: Arc<AtomicBool>,
) {
    let mut backoff = Backoff::new();
    while !stop.load(Ordering::SeqCst) {
        match connect_and_listen(&config, store.as_ref(), &on_record, &envelopes, &stop) {
            Ok(()) => backoff.reset(),
            Err(e) => warn!("cloud-messaging receiver: {e}"),
        }
        if envelopes.is_closed() {
            return;
        }
        let delay = backoff.next_delay();
        let until = std::time::Instant::now() + delay;
        while std::time::Instant::now() < until {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
}

fn load_credentials(store: &dyn SecureStore) -> Result<Option<FcmCredentials>> {
    match store.get(FCM_CREDENTIALS_ENTRY)? {
        Some(v) => match serde_json::from_str(&v) {
            Ok(c) => Ok(Some(c)),
            Err(_) => {
                warn!("stored cloud-messaging credentials are unreadable; re-registering");
                Ok(None)
            }
        },
        None => Ok(None),
    }
}

fn connect_and_listen(
    config: &FcmConfig,
    store: &dyn SecureStore,
    on_record: &RecordSink,
    envelopes: &mpsc::UnboundedSender<PushEnvelope>,
    stop: &Arc<AtomicBool>,
) -> Result<()> {
    let mut client = FcmClient::new(
        config.api_key.clone(),
        config.app_id.clone(),
        config.project_id.clone(),
    )
    .map_err(fcm_err)?;
    client.heartbeat_interval = config.heartbeat_interval;
    if let Some(v) = &config.vapid_key {
        client.vapid_key = v.clone();
    }
    client.android_app = config.android_app.as_ref().map(|a| AndroidApp {
        gcm_sender_id: a.gcm_sender_id.clone(),
        android_package: a.android_package.clone(),
        android_package_cert: a.android_package_cert.clone(),
    });

    let tx = envelopes.clone();
    let stop_raw = stop.clone();
    client.on_raw_message = Some(Arc::new(move |msg| {
        if stop_raw.load(Ordering::SeqCst) {
            return;
        }
        match PushEnvelope::from_fields(
            msg.app_data
                .iter()
                .map(|d| (d.key.as_str(), d.value.as_str())),
        ) {
            Some(env) => {
                let _ = tx.send(env);
            }
            None => debug!("ignoring a data message without a push envelope"),
        }
    }));
    let tx = envelopes.clone();
    let stop_data = stop.clone();
    client.on_data_message = Some(Arc::new(move |payload| {
        if stop_data.load(Ordering::SeqCst) {
            return;
        }
        let payload = Zeroizing::new(payload);
        match serde_json::from_slice::<serde_json::Value>(&payload)
            .ok()
            .and_then(|v| PushEnvelope::from_json(&v))
        {
            Some(env) => {
                let _ = tx.send(env);
            }
            None => debug!("ignoring an encrypted data message without a push envelope"),
        }
    }));

    let token = match load_credentials(store)? {
        Some(c) => {
            client.android_id = c.android_id;
            client.security_token = c.security_token;
            client.gcm_token = (!c.gcm_token.is_empty()).then(|| c.gcm_token.clone());
            client.fcm_token = Some(c.fcm_token.clone());
            client
                .load_keys(&c.private_key_b64, &c.auth_secret_b64)
                .map_err(fcm_err)?;
            c.fcm_token.clone()
        }
        None => {
            let (private_key_b64, auth_secret_b64) = client.create_new_keys().map_err(fcm_err)?;
            let (fcm_token, gcm_token, android_id, security_token) =
                client.register().map_err(fcm_err)?;
            let creds = FcmCredentials {
                android_id,
                security_token,
                fcm_token: fcm_token.clone(),
                gcm_token,
                private_key_b64,
                auth_secret_b64,
            };
            let json = Zeroizing::new(serde_json::to_string(&creds)?);
            store.put(FCM_CREDENTIALS_ENTRY, &json)?;
            info!("registered with cloud messaging");
            fcm_token
        }
    };
    on_record(DeviceRegistrationRecord::new(
        token,
        Environment::AndroidCloudMessaging,
    ));

    // Blocks until the connection ends.
    let r = client.start_listening().map_err(fcm_err);
    client.close();
    r
}
