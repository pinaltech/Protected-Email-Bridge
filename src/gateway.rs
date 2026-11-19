//! Per-account runtime context shared by the IMAP backend, the SMTP
//! pipeline and the synchroniser.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use tracing::warn;
use zeroize::Zeroizing;

use crate::account::{
    AddressMode, GatewayPassword, PersistedAccount, StateStore, authenticate_client,
};
use crate::api::ApiClient;
use crate::api::mail::is_unprocessable;
use crate::api::types::{Address, Label, MailSettings, Message, User, label_type};
use crate::config::{GatewaySettings, LocalArtifacts};
use crate::crypto::KeyRing;
use crate::error::{Error, Result};
use crate::imap::mailbox::UidValidityGenerator;
use crate::imap::mailbox::{MailboxKind, mailbox_name};
use crate::imap::store::{ImapSet, LocalMessage, MessageFlags};
use crate::keys;
use crate::literal;
use crate::smtp::dedup::{FailureThrottle, SendDedup};
use crate::util::{canonical_email, now_unix};

/// Shared handle to one IMAP mailbox set.
pub type SharedSet = Arc<RwLock<ImapSet>>;

/// Runtime state of one signed-in Account.
pub struct AccountContext {
    pub client: ApiClient,
    pub art: Arc<LocalArtifacts>,
    pub settings: Arc<GatewaySettings>,
    store: Arc<dyn StateStore>,
    persisted: Mutex<PersistedAccount>,
    user: RwLock<User>,
    addresses: RwLock<Vec<Address>>,
    user_ring: RwLock<Arc<KeyRing>>,
    addr_rings: RwLock<HashMap<String, Arc<KeyRing>>>,
    labels: RwLock<HashMap<String, Label>>,
    mail_settings: RwLock<Option<MailSettings>>,
    imap_sets: RwLock<HashMap<String, SharedSet>>,
    uidv: Arc<UidValidityGenerator>,
    pub dedup: SendDedup,
    pub smtp_throttle: Mutex<FailureThrottle>,
    sync_mode: AtomicBool,
    /// State of the push-notification client profile (§14).
    pub push: crate::push::AccountPushState,
}

impl AccountContext {
    /// Create the context from an unlocked user key ring and loaded data.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client: ApiClient,
        art: Arc<LocalArtifacts>,
        settings: Arc<GatewaySettings>,
        store: Arc<dyn StateStore>,
        persisted: PersistedAccount,
        user: User,
        addresses: Vec<Address>,
        user_ring: KeyRing,
    ) -> Arc<Self> {
        let ctx = Arc::new(Self {
            client,
            art,
            settings,
            store,
            persisted: Mutex::new(persisted),
            user: RwLock::new(user),
            addresses: RwLock::new(addresses),
            user_ring: RwLock::new(Arc::new(user_ring)),
            addr_rings: RwLock::new(HashMap::new()),
            labels: RwLock::new(HashMap::new()),
            mail_settings: RwLock::new(None),
            imap_sets: RwLock::new(HashMap::new()),
            uidv: Arc::new(UidValidityGenerator::new()),
            dedup: SendDedup::new(),
            smtp_throttle: Mutex::new(FailureThrottle::default()),
            sync_mode: AtomicBool::new(false),
            push: Default::default(),
        });
        ctx.unlock_address_rings();
        ctx
    }

    // ---- persisted state -------------------------------------------------

    /// Read a snapshot of the persisted state.
    pub fn persisted(&self) -> PersistedAccount {
        self.persisted.lock().expect("persisted lock").clone()
    }

    /// Mutate and save the persisted state.
    pub fn update_persisted(&self, f: impl FnOnce(&mut PersistedAccount)) -> Result<()> {
        let snapshot = {
            let mut p = self.persisted.lock().expect("persisted lock");
            f(&mut p);
            p.clone()
        };
        self.store.save(&snapshot)
    }

    pub fn user_id(&self) -> String {
        self.persisted().user_id
    }

    pub fn mode(&self) -> AddressMode {
        self.persisted().address_mode
    }

    pub fn gateway_password(&self) -> Result<GatewayPassword> {
        self.persisted().gateway_password()
    }

    pub fn salted_passphrase(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.persisted().salted_key_passphrase()
    }

    pub fn set_sync_mode(&self, on: bool) {
        self.sync_mode.store(on, Ordering::SeqCst);
    }

    pub fn in_sync_mode(&self) -> bool {
        self.sync_mode.load(Ordering::SeqCst)
    }

    // ---- user, addresses, keys -------------------------------------------

    pub fn user(&self) -> User {
        self.user.read().expect("user lock").clone()
    }

    pub fn set_user(&self, user: User) {
        *self.user.write().expect("user lock") = user;
    }

    pub fn user_ring(&self) -> Arc<KeyRing> {
        self.user_ring.read().expect("ring lock").clone()
    }

    pub fn addresses(&self) -> Vec<Address> {
        self.addresses.read().expect("addresses lock").clone()
    }

    pub fn set_addresses(&self, mut addrs: Vec<Address>) {
        crate::api::types::sort_addresses(&mut addrs);
        *self.addresses.write().expect("addresses lock") = addrs;
        self.unlock_address_rings();
    }

    /// The primary address (first after sorting by `Order`).
    pub fn primary_address(&self) -> Option<Address> {
        self.addresses
            .read()
            .expect("addresses lock")
            .first()
            .cloned()
    }

    pub fn address(&self, id: &str) -> Option<Address> {
        self.addresses
            .read()
            .expect("addresses lock")
            .iter()
            .find(|a| a.id == id)
            .cloned()
    }

    /// Owned address matching `email` (case-insensitive, `+tag` stripped).
    pub fn owned_address(&self, email: &str) -> Option<Address> {
        let want = canonical_email(email);
        self.addresses
            .read()
            .expect("addresses lock")
            .iter()
            .find(|a| canonical_email(&a.email) == want)
            .cloned()
    }

    /// Re-unlock every address key ring (after key/address changes).
    pub fn unlock_address_rings(&self) {
        let pass = match self.salted_passphrase() {
            Ok(p) => p,
            Err(e) => {
                warn!("no salted passphrase: {e}");
                return;
            }
        };
        let user_ring = self.user_ring();
        let mut rings = HashMap::new();
        for a in self.addresses() {
            let ring = keys::unlock_address_keyring(&a.keys, &user_ring, &pass);
            if ring.is_empty() {
                warn!(address = %a.id, "address has no unlockable key; it is unusable");
                continue;
            }
            rings.insert(a.id.clone(), Arc::new(ring));
        }
        *self.addr_rings.write().expect("rings lock") = rings;
    }

    /// Re-unlock the user key ring with the stored passphrase.
    pub fn reunlock_user_ring(&self) -> Result<()> {
        let pass = self.salted_passphrase()?;
        let ring = keys::unlock_user_keyring(&self.user().keys, &pass)?;
        *self.user_ring.write().expect("ring lock") = Arc::new(ring);
        self.unlock_address_rings();
        Ok(())
    }

    /// The key ring of an address.
    pub fn keyring(&self, address_id: &str) -> Result<Arc<KeyRing>> {
        self.addr_rings
            .read()
            .expect("rings lock")
            .get(address_id)
            .cloned()
            .ok_or(Error::KeyUnlock)
    }

    /// Client authentication (§10.2).
    pub fn authenticate(&self, username: &str, password: &str) -> Option<Address> {
        let gw = self.gateway_password().ok()?;
        let addrs = self.addresses();
        authenticate_client(&gw, &addrs, username, password).cloned()
    }

    // ---- settings ----------------------------------------------------------

    pub async fn mail_settings(&self) -> Result<MailSettings> {
        if let Some(s) = self.mail_settings.read().expect("settings lock").clone() {
            return Ok(s);
        }
        let s = self.client.get_mail_settings().await?;
        *self.mail_settings.write().expect("settings lock") = Some(s.clone());
        Ok(s)
    }

    pub fn set_mail_settings(&self, s: MailSettings) {
        *self.mail_settings.write().expect("settings lock") = Some(s);
    }

    // ---- labels ------------------------------------------------------------

    pub fn labels(&self) -> HashMap<String, Label> {
        self.labels.read().expect("labels lock").clone()
    }

    pub fn label(&self, id: &str) -> Option<Label> {
        self.labels.read().expect("labels lock").get(id).cloned()
    }

    pub fn set_labels(&self, labels: Vec<Label>) {
        *self.labels.write().expect("labels lock") =
            labels.into_iter().map(|l| (l.id.clone(), l)).collect();
    }

    pub fn put_label(&self, l: Label) {
        self.labels
            .write()
            .expect("labels lock")
            .insert(l.id.clone(), l);
    }

    pub fn remove_label(&self, id: &str) {
        self.labels.write().expect("labels lock").remove(id);
    }

    /// Fetch types 4, 3 and 1 from the Service and replace the cache.
    pub async fn reload_labels(&self) -> Result<()> {
        let labels = self
            .client
            .get_labels_of(&[label_type::SYSTEM, label_type::FOLDER, label_type::LABEL])
            .await?;
        self.set_labels(labels);
        Ok(())
    }

    /// Mailbox IDs a message belongs to: its wanted label IDs (§11.6).
    pub fn wanted_mailboxes(&self, label_ids: &[String]) -> Vec<String> {
        let labels = self.labels.read().expect("labels lock");
        label_ids
            .iter()
            .filter(|id| labels.get(*id).is_some_and(Label::is_wanted))
            .cloned()
            .collect()
    }

    /// Label IDs not known locally.
    pub fn unknown_labels(&self, label_ids: &[String]) -> Vec<String> {
        let labels = self.labels.read().expect("labels lock");
        label_ids
            .iter()
            .filter(|id| !labels.contains_key(*id))
            .cloned()
            .collect()
    }

    // ---- IMAP sets ---------------------------------------------------------

    pub fn imap_sets(&self) -> Vec<SharedSet> {
        self.imap_sets
            .read()
            .expect("sets lock")
            .values()
            .cloned()
            .collect()
    }

    /// The set bound to `address_id` (exact).
    pub fn imap_set(&self, address_id: &str) -> Option<SharedSet> {
        self.imap_sets
            .read()
            .expect("sets lock")
            .get(address_id)
            .cloned()
    }

    /// The set a message owned by `address_id` belongs to (§12.1 step 8,
    /// §12.3.5): combined → the single set; split → that address's set.
    pub fn imap_set_for_message(&self, address_id: &str) -> Option<SharedSet> {
        match self.mode() {
            AddressMode::Combined => self.imap_sets().into_iter().next(),
            AddressMode::Split => self.imap_set(address_id),
        }
    }

    /// The set a client logging in as `address` uses (§10.3, §11.4.1).
    pub fn imap_set_for_login(&self, address: &Address) -> Option<SharedSet> {
        self.imap_set_for_message(&address.id)
    }

    /// Discard and rebuild the IMAP set(s) and their mailboxes (§10.3).
    pub fn rebuild_imap_sets(&self) -> Result<()> {
        let mut sets = HashMap::new();
        match self.mode() {
            AddressMode::Combined => {
                if let Some(p) = self.primary_address() {
                    sets.insert(
                        p.id.clone(),
                        Arc::new(RwLock::new(ImapSet::new(p.id, self.uidv.clone()))),
                    );
                }
            }
            AddressMode::Split => {
                for a in self.addresses().into_iter().filter(Address::is_enabled) {
                    sets.insert(
                        a.id.clone(),
                        Arc::new(RwLock::new(ImapSet::new(a.id, self.uidv.clone()))),
                    );
                }
            }
        }
        {
            let old = std::mem::replace(&mut *self.imap_sets.write().expect("sets lock"), sets);
            for s in old.values() {
                s.write().expect("set lock").clear();
            }
        }
        for s in self.imap_sets() {
            self.populate_mailboxes(&s)?;
        }
        Ok(())
    }

    /// Add an IMAP set for an address (split mode, §12.3.3).
    pub fn add_imap_set(&self, address_id: &str) -> Result<()> {
        let set = Arc::new(RwLock::new(ImapSet::new(address_id, self.uidv.clone())));
        self.populate_mailboxes(&set)?;
        self.imap_sets
            .write()
            .expect("sets lock")
            .insert(address_id.to_string(), set);
        Ok(())
    }

    /// Remove an IMAP set and its local data.
    pub fn remove_imap_set(&self, address_id: &str) {
        if let Some(s) = self
            .imap_sets
            .write()
            .expect("sets lock")
            .remove(address_id)
        {
            s.write().expect("set lock").clear();
        }
    }

    /// Re-bind the combined set to a new primary address (§10.3).
    pub fn rebind_combined(&self) {
        if self.mode() != AddressMode::Combined {
            return;
        }
        let Some(p) = self.primary_address() else {
            return;
        };
        let mut sets = self.imap_sets.write().expect("sets lock");
        if sets.contains_key(&p.id) {
            return;
        }
        if let Some(key) = sets.keys().next().cloned()
            && let Some(set) = sets.remove(&key)
        {
            set.write().expect("set lock").bound_address_id = p.id.clone();
            sets.insert(p.id, set);
        }
    }

    /// Create placeholders, the recovery mailbox and one mailbox per wanted
    /// label (§12.1 step 2).
    pub fn populate_mailboxes(&self, set: &SharedSet) -> Result<()> {
        let labels = self.labels();
        let service_ids: HashSet<String> = labels.keys().cloned().collect();
        let mut s = set.write().expect("set lock");
        s.ensure_local_mailboxes(&self.art.recovery_mailbox, &service_ids)?;
        let mut sorted: Vec<&Label> = labels.values().filter(|l| l.is_wanted()).collect();
        sorted.sort_by_key(|l| (l.kind, l.path.matches('/').count(), l.id.clone()));
        for l in sorted {
            place_label_mailbox(&mut s, l, &labels, &mut Vec::new())?;
        }
        Ok(())
    }

    /// Create or rename the mailbox of `label` in every set (§12.3.4).
    pub fn apply_label(&self, label: &Label) -> Result<()> {
        let labels = self.labels();
        for set in self.imap_sets() {
            let mut s = set.write().expect("set lock");
            place_label_mailbox(&mut s, label, &labels, &mut Vec::new())?;
        }
        Ok(())
    }

    /// Delete a label's mailbox in every set.
    pub fn delete_label_mailbox(&self, id: &str) {
        for set in self.imap_sets() {
            set.write().expect("set lock").delete_mailbox(id);
        }
    }

    // ---- message building ----------------------------------------------------

    /// Fetch a full message, its attachments, decrypt and build the literal.
    /// Returns `None` if the message no longer exists (HTTP 422).
    pub async fn fetch_and_build(&self, id: &str) -> Result<Option<(Message, Vec<u8>, bool)>> {
        let msg = match self.client.get_message(id).await {
            Ok(m) => m,
            Err(e) if is_unprocessable(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        let (literal, failed) = self.build(&msg).await?;
        Ok(Some((msg, literal, failed)))
    }

    /// Download attachments and build the literal for a full message.
    pub async fn build(&self, msg: &Message) -> Result<(Vec<u8>, bool)> {
        let downloads = msg
            .attachments
            .iter()
            .map(|a| self.client.get_attachment(&a.id));
        let packets: Vec<Vec<u8>> = futures::future::try_join_all(downloads).await?;
        let ring = self.keyring(&msg.metadata.address_id).ok();
        let msg2 = msg.clone();
        let art = self.art.clone();
        let (literal, failed) = tokio::task::spawn_blocking(move || match ring {
            Some(r) => literal::decrypt_and_build(&msg2, &r, packets, &art),
            None => {
                let empty = KeyRing::default();
                literal::decrypt_and_build(&msg2, &empty, packets, &art)
            }
        })
        .await
        .map_err(|e| Error::Other(e.to_string()))?;
        self.record_build(&msg.metadata.id, failed);
        Ok((literal, failed))
    }

    /// Record or clear a build failure (§11.8.5).
    pub fn record_build(&self, id: &str, failed: bool) {
        let present = self.persisted().sync.failed_message_ids.contains(id);
        if failed != present {
            let _ = self.update_persisted(|p| {
                if failed {
                    p.sync.failed_message_ids.insert(id.to_string());
                } else {
                    p.sync.failed_message_ids.remove(id);
                }
            });
        }
    }

    /// Turn a Service message and its literal into a local message.
    pub fn local_message(&self, msg: &Message, literal: Vec<u8>, failed: bool) -> LocalMessage {
        let mut lm = LocalMessage::new(&msg.metadata.id);
        lm.literal = Some(Arc::new(literal));
        lm.failed = failed;
        lm.internal_date = if msg.metadata.time > 0 {
            msg.metadata.time
        } else {
            now_unix()
        };
        lm.flags = MessageFlags::from_metadata(&msg.metadata);
        lm.label_ids = msg.metadata.label_ids.clone();
        lm.address_id = msg.metadata.address_id.clone();
        lm
    }
}

/// Place (create or rename) a label's mailbox, resolving name conflicts
/// (§11.14).
pub fn place_label_mailbox(
    set: &mut ImapSet,
    label: &Label,
    labels: &HashMap<String, Label>,
    chain: &mut Vec<String>,
) -> Result<()> {
    if !label.is_wanted() {
        return Ok(());
    }
    let Some(name) = mailbox_name(label, labels) else {
        return Ok(());
    };
    let kind = match label.kind {
        label_type::SYSTEM => MailboxKind::System,
        label_type::FOLDER => MailboxKind::Folder,
        _ => MailboxKind::Label,
    };
    chain.push(label.id.clone());
    if let Some(holder) = set
        .mailbox_by_name(&name)
        .map(|m| (m.id.clone(), m.name.clone()))
        && holder.0 != label.id
    {
        match labels.get(&holder.0) {
            None => {
                set.delete_mailbox(&holder.0);
            }
            Some(hl) => {
                let new_name = mailbox_name(hl, labels).unwrap_or_default();
                if crate::imap::store::names_equal(&new_name, &holder.1) {
                    return Err(Error::Invalid(format!(
                        "mailbox name conflict: {} is held by label {}",
                        name.join("/"),
                        hl.id
                    )));
                }
                if chain.contains(&hl.id) {
                    // Cycle (e.g. a swap): temporarily rename the holder.
                    let mut tmp = holder.1.clone();
                    if let Some(last) = tmp.last_mut() {
                        *last = format!("tmp_{last}");
                    }
                    set.rename_mailbox(&hl.id, tmp)?;
                } else {
                    place_label_mailbox(set, hl, labels, chain)?;
                }
            }
        }
    }
    set.create_mailbox(&label.id, name, kind)
}

/// Outcome of an IMAP/SMTP client login attempt.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientLoginError {
    #[error("invalid username or password")]
    Invalid,
    #[error("login blocked")]
    Blocked,
}

/// The gateway: registry of signed-in accounts plus shared admission
/// control. This is the main entry point for embedding applications.
pub struct Gateway {
    pub cfg: Arc<crate::config::DeploymentConfig>,
    pub art: Arc<LocalArtifacts>,
    pub settings: Arc<GatewaySettings>,
    pub store: Arc<dyn StateStore>,
    accounts: RwLock<Vec<Arc<AccountContext>>>,
    pub login_throttle: crate::imap::admission::LoginThrottle,
    pub connections: crate::imap::admission::ConnectionRateLimiter,
    pub sessions: crate::imap::admission::SessionCounter,
    /// Bumped whenever the set of stored sessions changes (§14.3.3).
    session_changes: Arc<tokio::sync::watch::Sender<u64>>,
}

impl Gateway {
    pub fn new(
        cfg: crate::config::DeploymentConfig,
        art: LocalArtifacts,
        settings: GatewaySettings,
        store: Arc<dyn StateStore>,
    ) -> Arc<Self> {
        let jail = settings.imap_login_jail;
        Arc::new(Self {
            cfg: Arc::new(cfg),
            art: Arc::new(art),
            settings: Arc::new(settings),
            store,
            accounts: RwLock::new(Vec::new()),
            login_throttle: crate::imap::admission::LoginThrottle::new(jail),
            connections: Default::default(),
            sessions: Default::default(),
            session_changes: Arc::new(tokio::sync::watch::channel(0).0),
        })
    }

    /// Changes whenever a session is added, rotated, replaced or removed.
    pub fn subscribe_sessions(&self) -> tokio::sync::watch::Receiver<u64> {
        self.session_changes.subscribe()
    }

    fn notify_sessions_changed(&self) {
        self.session_changes.send_modify(|v| *v = v.wrapping_add(1));
    }

    /// The live account whose current session UID is `uid` (§14.4.3 step 5).
    pub fn account_by_session_uid(&self, uid: &str) -> Option<Arc<AccountContext>> {
        self.accounts()
            .into_iter()
            .find(|a| !uid.is_empty() && a.persisted().session_uid == uid)
    }

    /// Add a live account directly (tests only).
    #[cfg(test)]
    pub(crate) fn insert_account(&self, ctx: Arc<AccountContext>) {
        self.accounts.write().expect("accounts lock").push(ctx);
    }

    /// The live account with this UserID.
    pub fn account(&self, user_id: &str) -> Option<Arc<AccountContext>> {
        self.accounts().into_iter().find(|a| a.user_id() == user_id)
    }

    pub fn accounts(&self) -> Vec<Arc<AccountContext>> {
        self.accounts.read().expect("accounts lock").clone()
    }

    /// Whether a UserID is already connected (§5.1.7).
    pub fn is_connected_user(&self, user_id: &str) -> bool {
        self.accounts().iter().any(|a| a.user_id() == user_id)
    }

    pub fn new_client(&self) -> Result<ApiClient> {
        ApiClient::new(self.cfg.clone())
    }

    fn install_listeners(&self, ctx: &Arc<AccountContext>) {
        let store_ctx = Arc::downgrade(ctx);
        let client = ctx.client.clone();
        let deauth_ctx = Arc::downgrade(ctx);
        let changes = self.session_changes.clone();
        let changes2 = self.session_changes.clone();
        tokio::spawn(async move {
            client
                .set_token_listener(Arc::new(move |t: &crate::api::SessionTokens| {
                    if let Some(c) = store_ctx.upgrade() {
                        let (uid, rt) = (t.uid.clone(), t.refresh_token.clone());
                        let _ = c.update_persisted(|p| {
                            p.session_uid = uid;
                            p.refresh_token = rt;
                        });
                        changes.send_modify(|v| *v = v.wrapping_add(1));
                    }
                }))
                .await;
            client
                .set_deauth_listener(Arc::new(move || {
                    if let Some(c) = deauth_ctx.upgrade() {
                        warn!("session deauthenticated; account signed out");
                        let _ = c.update_persisted(|p| p.clear_session());
                        changes2.send_modify(|v| *v = v.wrapping_add(1));
                    }
                }))
                .await;
        });
    }

    /// Register a freshly completed login (§5.4 step 7) and build its local
    /// state. `client` must be the client used for the login.
    pub async fn add_login(
        &self,
        client: ApiClient,
        username: &str,
        logged: crate::auth::LoggedIn,
    ) -> Result<Arc<AccountContext>> {
        let primary_email = logged
            .addresses
            .first()
            .map(|a| a.email.clone())
            .unwrap_or_else(|| logged.user.email.clone());
        let mut archive = self.store.load_archive()?;
        let gw = archive.get_or_generate(&primary_email);
        self.store.save_archive(&archive)?;
        let mut p = PersistedAccount::new(&logged.user.id, username, &primary_email, &gw);
        p.session_uid = logged.tokens.uid.clone();
        p.refresh_token = logged.tokens.refresh_token.clone();
        p.set_salted_key_passphrase(&logged.salted_key_passphrase);
        self.store.save(&p)?;
        let ctx = AccountContext::new(
            client,
            self.art.clone(),
            self.settings.clone(),
            self.store.clone(),
            p,
            logged.user,
            logged.addresses,
            logged.user_keyring,
        );
        self.install_listeners(&ctx);
        ctx.reload_labels().await?;
        ctx.rebuild_imap_sets()?;
        self.accounts
            .write()
            .expect("accounts lock")
            .push(ctx.clone());
        self.notify_sessions_changed();
        Ok(ctx)
    }

    /// Resume every stored, signed-in account at start-up (§5.5.1).
    pub async fn resume_all(&self) -> Result<Vec<Arc<AccountContext>>> {
        let mut out = Vec::new();
        for mut p in self.store.load_all()? {
            if !p.is_signed_in() {
                continue;
            }
            let client = self.new_client()?;
            match crate::auth::resume(&client, &p.session_uid, &p.refresh_token).await {
                Ok(t) => {
                    p.session_uid = t.uid;
                    p.refresh_token = t.refresh_token;
                    self.store.save(&p)?;
                }
                Err(Error::Deauthenticated) => {
                    p.clear_session();
                    self.store.save(&p)?;
                    continue;
                }
                Err(e) => {
                    warn!(user = %p.user_id, "could not resume account: {e}");
                    continue;
                }
            }
            let pass = p.salted_key_passphrase()?;
            let (user, ring) = crate::auth::unlock_from_passphrase(&client, &pass).await?;
            let addresses = client.get_addresses().await?;
            let ctx = AccountContext::new(
                client,
                self.art.clone(),
                self.settings.clone(),
                self.store.clone(),
                p,
                user,
                addresses,
                ring,
            );
            self.install_listeners(&ctx);
            ctx.reload_labels().await?;
            ctx.rebuild_imap_sets()?;
            self.accounts
                .write()
                .expect("accounts lock")
                .push(ctx.clone());
            self.notify_sessions_changed();
            out.push(ctx);
        }
        Ok(out)
    }

    /// Explicit logout: revoke the session and forget local state.
    pub async fn logout(&self, user_id: &str) -> Result<()> {
        let ctx = {
            let mut accs = self.accounts.write().expect("accounts lock");
            let pos = accs.iter().position(|a| a.user_id() == user_id);
            pos.map(|i| accs.remove(i))
        };
        if let Some(ctx) = ctx {
            let _ = ctx.client.logout().await;
            for s in ctx.imap_sets() {
                s.write().expect("set lock").clear();
            }
            ctx.update_persisted(|p| p.clear_session())?;
            self.notify_sessions_changed();
        }
        Ok(())
    }

    /// Change an account's address mode (§10.3): discard local IMAP state,
    /// rebuild and resync. The caller restarts sync via its `Synchroniser`.
    pub fn set_address_mode(&self, ctx: &AccountContext, mode: AddressMode) -> Result<()> {
        ctx.update_persisted(|p| {
            p.address_mode = mode;
            p.sync = Default::default();
        })?;
        ctx.rebuild_imap_sets()
    }

    fn find_credentials(
        &self,
        username: &str,
        password: &str,
    ) -> Option<(Arc<AccountContext>, Address)> {
        self.accounts()
            .into_iter()
            .find_map(|a| a.authenticate(username, password).map(|addr| (a, addr)))
    }

    /// IMAP LOGIN / AUTHENTICATE PLAIN (§11.4.1).
    pub fn imap_login(
        &self,
        username: &str,
        password: &str,
    ) -> std::result::Result<crate::imap::backend::ImapBackend, ClientLoginError> {
        use crate::imap::admission::LoginFailure;
        if self.login_throttle.is_jailed() {
            return Err(ClientLoginError::Blocked);
        }
        match self
            .find_credentials(username, password)
            .and_then(|(ctx, addr)| ctx.imap_set_for_login(&addr).map(|s| (ctx, s, addr)))
        {
            Some((ctx, set, addr)) => {
                self.login_throttle.record_success();
                Ok(crate::imap::backend::ImapBackend::new(ctx, set, addr))
            }
            None => match self.login_throttle.record_failure() {
                LoginFailure::Blocked => Err(ClientLoginError::Blocked),
                LoginFailure::Failed => Err(ClientLoginError::Invalid),
            },
        }
    }
}

impl crate::smtp::SmtpAuthenticator for Gateway {
    fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Option<(Arc<AccountContext>, String)> {
        self.find_credentials(username, password)
            .map(|(ctx, addr)| (ctx, addr.id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lbl(id: &str, name: &str) -> Label {
        Label {
            id: id.into(),
            name: name.into(),
            path: name.into(),
            kind: 1,
            ..Default::default()
        }
    }

    #[test]
    fn swap_names() {
        let mut set = ImapSet::new("a", Arc::new(UidValidityGenerator::new()));
        let mut labels = HashMap::new();
        labels.insert("1".to_string(), lbl("1", "x"));
        labels.insert("2".to_string(), lbl("2", "y"));
        for l in labels.values() {
            place_label_mailbox(&mut set, l, &labels, &mut Vec::new()).unwrap();
        }
        // Swap.
        labels.insert("1".to_string(), lbl("1", "y"));
        labels.insert("2".to_string(), lbl("2", "x"));
        place_label_mailbox(&mut set, &labels["1"], &labels, &mut Vec::new()).unwrap();
        place_label_mailbox(&mut set, &labels["2"], &labels, &mut Vec::new()).unwrap();
        assert_eq!(set.mailbox("1").unwrap().name, vec!["Labels", "y"]);
        assert_eq!(set.mailbox("2").unwrap().name, vec!["Labels", "x"]);
    }
}
