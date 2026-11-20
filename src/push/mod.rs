//! Mobile push-notification client profile (§14).
//!
//! * [`device_key`] — the per-installation OpenPGP device key and its
//!   secure storage (§14.2).
//! * [`registration`] — environment codes, the platform registration record
//!   and the background registration process (§14.3).
//! * [`envelope`] — the push envelope and its decryption (§14.4).
//! * [`payload`] — notification payloads and presentation (§14.5).
//! * [`queue`] — notification quick actions and the outgoing-action queue
//!   (§14.6).
//! * [`open`] — opening a notification from fresh server state (§14.7).
//! * [`fcm`] — the Android cloud-messaging Push Provider transport
//!   (environment 4), built on `fcm_receiver_rs`.
//!
//! [`NotificationClient`] ties these together for a [`Gateway`]'s accounts.
//! Mobile embedders set `DeploymentConfig::app_platform` to the mobile
//! operating system (e.g. `android`) so that `x-pm-appversion` reads
//! `android-<product>@<semver>` (§14.8). Device registration alone can be
//! given its own product, version and platform
//! (`DeploymentConfig::push_app_product_token`, `push_app_version`,
//! `push_app_platform`).

pub mod device_key;
pub mod envelope;
pub mod fcm;
pub mod open;
pub mod payload;
pub mod queue;
pub mod registration;
pub mod seen;
#[cfg(test)]
pub(crate) mod test_support;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::api::types::Conversation;
use crate::error::{Error, Result};
use crate::gateway::Gateway;

pub use device_key::{DeviceKey, DeviceKeyManager, MemorySecureStore, SecureStore};
pub use envelope::PushEnvelope;
pub use open::{OpenedConversation, OpenedMessage};
pub use payload::{EmailAction, Notification, Presentation, Sender};
pub use queue::QuickAction;
pub use registration::{
    ApiConnectivity, Connectivity, DeviceRegistrationRecord, Environment, Registrar,
    RegistrationObserver,
};

/// Per-account state of the push profile, held by
/// [`crate::gateway::AccountContext`].
#[derive(Default)]
pub struct AccountPushState {
    /// Serialises the deferred remote phase of the action queue.
    pub(crate) queue_runner: tokio::sync::Mutex<()>,
    conversations: RwLock<HashMap<String, Conversation>>,
    open_drafts: Mutex<HashSet<String>>,
}

impl AccountPushState {
    /// The locally stored conversation.
    pub fn conversation(&self, id: &str) -> Option<Conversation> {
        self.conversations
            .read()
            .expect("conversations lock")
            .get(id)
            .cloned()
    }

    pub fn put_conversation(&self, c: Conversation) {
        self.conversations
            .write()
            .expect("conversations lock")
            .insert(c.id.clone(), c);
    }

    /// Record that a draft is open in a local composer (§14.7.1 step 4a).
    pub fn set_draft_open(&self, message_id: &str, open: bool) {
        let mut d = self.open_drafts.lock().expect("drafts lock");
        if open {
            d.insert(message_id.to_string());
        } else {
            d.remove(message_id);
        }
    }

    pub fn is_draft_open(&self, message_id: &str) -> bool {
        self.open_drafts
            .lock()
            .expect("drafts lock")
            .contains(message_id)
    }
}

/// A decrypted notification and the Account it belongs to.
#[derive(Debug, Clone)]
pub struct ReceivedNotification {
    pub user_id: String,
    pub session_uid: String,
    pub notification: Notification,
}

/// Displays notifications. Implementations key displayed notifications by
/// (Account, message ID), group them per Account, and render all text as
/// plain text (§14.5.2, §15).
pub trait NotificationPresenter: Send + Sync {
    fn present(&self, user_id: &str, presentation: &Presentation);
}

/// A log line for a dropped notification that never includes plaintext.
fn drop_reason(e: &Error) -> String {
    match e {
        Error::Json(j) => format!(
            "deserialisation error ({:?} at line {}, column {})",
            j.classify(),
            j.line(),
            j.column()
        ),
        Error::Crypto(_) | Error::Pgp(_) => "cryptographic error".into(),
        other => format!("{other}"),
    }
}

/// The Notification Client for a Gateway's accounts.
pub struct NotificationClient {
    gateway: Arc<Gateway>,
    secure_store: Arc<dyn SecureStore>,
    keys: Arc<DeviceKeyManager>,
    connectivity: Arc<dyn Connectivity>,
    records: watch::Sender<Option<DeviceRegistrationRecord>>,
    seen: seen::SeenNotifications,
    /// Set once stored accounts are resumed; envelopes wait until then.
    accounts_ready: watch::Sender<bool>,
}

impl NotificationClient {
    /// `connectivity` defaults to [`ApiConnectivity`] on a fresh client.
    pub fn new(
        gateway: Arc<Gateway>,
        secure_store: Arc<dyn SecureStore>,
        connectivity: Option<Arc<dyn Connectivity>>,
    ) -> Result<Arc<Self>> {
        let connectivity = match connectivity {
            Some(c) => c,
            None => Arc::new(ApiConnectivity::new(gateway.new_client()?)),
        };
        Ok(Arc::new(Self {
            gateway,
            keys: Arc::new(DeviceKeyManager::new(secure_store.clone())),
            seen: seen::SeenNotifications::new(secure_store.clone()),
            accounts_ready: watch::channel(false).0,
            secure_store,
            connectivity,
            records: watch::channel(None).0,
        }))
    }

    /// Declare that every stored account has been resumed (or has failed
    /// to resume), so that received envelopes can be mapped to their
    /// Accounts. Until then [`Self::run`] holds envelopes unprocessed:
    /// messages delivered on connect would otherwise find no session and be
    /// discarded.
    pub fn mark_accounts_ready(&self) {
        self.accounts_ready.send_replace(true);
    }

    pub fn accounts_ready(&self) -> bool {
        *self.accounts_ready.borrow()
    }

    /// Start-up helper: [`Gateway::resume_all`], then
    /// [`Self::mark_accounts_ready`] and [`Self::resume_queues`]. Accounts
    /// are marked ready even if resuming fails, so that envelopes are not
    /// held forever; the error is returned.
    pub async fn resume_accounts(&self) -> Result<Vec<Arc<crate::gateway::AccountContext>>> {
        let r = self.gateway.resume_all().await;
        self.mark_accounts_ready();
        self.resume_queues();
        r
    }

    pub fn device_keys(&self) -> &Arc<DeviceKeyManager> {
        &self.keys
    }

    /// Supply or update the platform's registration record (§14.3.1).
    pub fn set_registration_record(&self, record: DeviceRegistrationRecord) {
        self.records.send_if_modified(|cur| {
            if cur.as_ref() == Some(&record) {
                false
            } else {
                *cur = Some(record);
                true
            }
        });
    }

    /// Start the background registration process (§14.3.3).
    pub fn start_registration(
        &self,
        observer: Option<Arc<dyn RegistrationObserver>>,
    ) -> JoinHandle<()> {
        Registrar::new(
            self.gateway.clone(),
            self.keys.clone(),
            self.connectivity.clone(),
            self.records.subscribe(),
            observer,
        )
        .spawn()
    }

    /// Decrypt and parse an envelope and map it to its Account (§14.4.3).
    /// Failures are logged without plaintext and returned; the notification
    /// must then be dropped. `Ok(None)`: no local session matches the UID,
    /// so the notification is discarded.
    pub fn receive(&self, envelope: &PushEnvelope) -> Result<Option<ReceivedNotification>> {
        let notification = match envelope.open(&self.keys) {
            Ok(n) => n,
            Err(e) => {
                warn!("dropping push notification: {}", drop_reason(&e));
                return Err(e);
            }
        };
        let Some(ctx) = self.gateway.account_by_session_uid(&envelope.uid) else {
            debug!("discarding push notification for an unknown session");
            return Ok(None);
        };
        Ok(Some(ReceivedNotification {
            user_id: ctx.user_id(),
            session_uid: envelope.uid.clone(),
            notification,
        }))
    }

    /// Receive envelopes until the channel closes, presenting each one.
    ///
    /// Nothing is processed before [`Self::mark_accounts_ready`]; envelopes
    /// wait in the channel. Deliveries already processed — including in an
    /// earlier run of the application — are skipped.
    pub async fn run(
        self: Arc<Self>,
        mut envelopes: mpsc::UnboundedReceiver<PushEnvelope>,
        presenter: Arc<dyn NotificationPresenter>,
    ) {
        let mut ready = self.accounts_ready.subscribe();
        if ready.wait_for(|r| *r).await.is_err() {
            return;
        }
        while let Some(env) = envelopes.recv().await {
            self.process(&env, presenter.as_ref());
        }
    }

    /// Handle one envelope: skip redeliveries, decrypt, map, present, and
    /// remember it. Dropped and discarded envelopes are remembered too, so
    /// a redelivery is not processed (or logged) again.
    pub fn process(&self, env: &PushEnvelope, presenter: &dyn NotificationPresenter) {
        if self.seen.contains(env) {
            debug!("skipping a redelivered push notification");
            return;
        }
        if let Ok(Some(r)) = self.receive(env) {
            let p = Presentation::of(&r.notification);
            if p != Presentation::Ignore {
                presenter.present(&r.user_id, &p);
            }
        }
        if let Err(e) = self.seen.insert(env) {
            warn!("could not record a processed push notification: {e}");
        }
    }

    /// Run a quick action from an `email` notification (§14.6.2).
    /// `remaining` is the OS-reported background time left, if known.
    pub async fn quick_action(
        &self,
        user_id: &str,
        action: QuickAction,
        message_id: &str,
        remaining: Option<Duration>,
    ) -> Result<()> {
        let ctx = self.gateway.account(user_id);
        queue::execute(ctx.as_ref(), action, message_id, remaining).await
    }

    /// Resolve the message of a tapped `email` notification (§14.7.1).
    pub async fn open_message(&self, user_id: &str, message_id: &str) -> Result<OpenedMessage> {
        let ctx = self
            .gateway
            .account(user_id)
            .ok_or_else(|| Error::NotFound("account is not signed in".into()))?;
        open::resolve_message(&ctx, message_id).await
    }

    /// Open the conversation holding a notification's message (§14.7.2).
    pub async fn open_conversation(
        &self,
        user_id: &str,
        conversation_id: &str,
        label_id: &str,
        snooze_reminder: bool,
    ) -> Result<Option<OpenedConversation>> {
        let ctx = self
            .gateway
            .account(user_id)
            .ok_or_else(|| Error::NotFound("account is not signed in".into()))?;
        open::open_conversation(
            &ctx,
            self.connectivity.as_ref(),
            conversation_id,
            label_id,
            snooze_reminder,
        )
        .await
    }

    /// Resume the deferred remote phase of every account's queue (e.g. at
    /// start-up, after [`Gateway::resume_all`]).
    pub fn resume_queues(&self) {
        for ctx in self.gateway.accounts() {
            if let Err(e) = queue::apply_local(&ctx) {
                warn!("could not apply queued quick actions locally: {e}");
            }
            if ctx
                .persisted()
                .action_queue
                .iter()
                .any(|r| r.remote_pending)
            {
                queue::spawn_remote(ctx);
            }
        }
    }

    /// Start the Android cloud-messaging transport (§14.3.4 environment 4):
    /// its device token feeds the registration record, and its data
    /// messages are received and presented once accounts are ready
    /// ([`Self::resume_accounts`] / [`Self::mark_accounts_ready`]).
    pub fn start_fcm(
        self: &Arc<Self>,
        config: fcm::FcmConfig,
        presenter: Arc<dyn NotificationPresenter>,
    ) -> Result<fcm::FcmPushProvider> {
        let (tx, rx) = mpsc::unbounded_channel();
        let me = Arc::downgrade(self);
        let provider = fcm::FcmPushProvider::start(
            config,
            self.secure_store.clone(),
            Arc::new(move |record| {
                if let Some(c) = me.upgrade() {
                    c.set_registration_record(record);
                }
            }),
            tx,
        )?;
        tokio::spawn(self.clone().run(rx, presenter));
        Ok(provider)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::push::device_key::tests::service_encrypt;
    use crate::push::test_support;

    #[derive(Default)]
    struct Recorder(Mutex<Vec<(String, Presentation)>>);
    impl NotificationPresenter for Recorder {
        fn present(&self, user_id: &str, p: &Presentation) {
            self.0
                .lock()
                .unwrap()
                .push((user_id.to_string(), p.clone()));
        }
    }

    fn email(id: &str) -> String {
        format!(
            r#"{{"type":"email","data":{{"title":"","subtitle":"","body":"s","messageId":"{id}",
            "sender":{{"Name":"","Address":"","Group":""}},"badge":1,"largeIcon":"","smallIcon":""}}}}"#
        )
    }

    async fn client(
        base: &str,
        store: Arc<dyn SecureStore>,
    ) -> (Arc<NotificationClient>, Arc<Gateway>) {
        let gw = Gateway::new(
            (*test_support::config(base)).clone(),
            Default::default(),
            Default::default(),
            Arc::new(test_support::MemStateStore::default()),
        );
        gw.insert_account(test_support::account(base).await);
        (
            NotificationClient::new(gw.clone(), store, None).unwrap(),
            gw,
        )
    }

    async fn settle() {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    #[tokio::test]
    async fn holds_until_ready_and_skips_redeliveries_across_restarts() {
        let store: Arc<dyn SecureStore> = Arc::new(MemorySecureStore::default());
        let (nc, _gw) = client("http://127.0.0.1:9", store.clone()).await;
        let pk = nc
            .device_keys()
            .get_or_create()
            .unwrap()
            .armored_public_key()
            .unwrap();
        let env = |id: &str, uid: &str| PushEnvelope {
            uid: uid.into(),
            encrypted_message: service_encrypt(&pk, email(id).as_bytes()),
        };
        let m1 = env("m1", "uid-1");
        let unknown = env("m9", "uid-other");

        let rec = Arc::new(Recorder::default());
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(nc.clone().run(rx, rec.clone()));
        tx.send(m1.clone()).unwrap();
        tx.send(unknown.clone()).unwrap();
        settle().await;
        assert!(
            rec.0.lock().unwrap().is_empty(),
            "held until accounts are ready"
        );

        nc.mark_accounts_ready();
        settle().await;
        {
            let got = rec.0.lock().unwrap();
            assert_eq!(got.len(), 1);
            assert_eq!(got[0].0, "user-1");
            assert!(
                matches!(&got[0].1, Presentation::ShowEmail { message_id, .. } if message_id == "m1")
            );
        }

        // Redelivery in the same run.
        tx.send(m1.clone()).unwrap();
        settle().await;
        assert_eq!(rec.0.lock().unwrap().len(), 1);

        // "Restart": a new client over the same secure store.
        drop(tx);
        let (nc2, _gw2) = client("http://127.0.0.1:9", store.clone()).await;
        nc2.mark_accounts_ready();
        let rec2 = Recorder::default();
        nc2.process(&m1, &rec2);
        assert!(
            rec2.0.lock().unwrap().is_empty(),
            "redelivery after restart is skipped"
        );
        let m2 = PushEnvelope {
            uid: "uid-1".into(),
            encrypted_message: service_encrypt(&pk, email("m2").as_bytes()),
        };
        nc2.process(&m2, &rec2);
        assert_eq!(
            rec2.0.lock().unwrap().len(),
            1,
            "new deliveries still shown"
        );
    }
}
