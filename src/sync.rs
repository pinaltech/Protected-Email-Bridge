//! Initial synchronisation (§12.1) and incremental event processing
//! (§12.2, §12.3).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::account::AddressMode;
use crate::api::backoff::with_backoff;
use crate::api::mail::{MessageFilter, is_unprocessable};
use crate::api::types::{
    Event, Label, MessageMetadata, event_action, label_id, label_type, refresh_flag,
};
use crate::config::limits::{self, GIB, MIB};
use crate::error::{Error, Result};
use crate::gateway::AccountContext;
use crate::imap::store::MessageFlags;
use crate::util::jitter;

type Built = (crate::api::types::Message, Vec<u8>, bool);

async fn fetch_with_backoff(
    ctx: Arc<AccountContext>,
    id: String,
    throttled: Arc<std::sync::atomic::AtomicBool>,
) -> Result<Option<Built>> {
    with_backoff(|| {
        let ctx = ctx.clone();
        let id = id.clone();
        let throttled = throttled.clone();
        async move {
            let r = ctx.fetch_and_build(&id).await;
            if let Err(e) = &r
                && e.is_backoff_retryable()
            {
                throttled.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            r
        }
    })
    .await
}

/// Download/build memory derived from the sync memory budget (§12.1).
pub fn memory_budgets(configured: u64, system_ram: Option<u64>) -> (u64, u64) {
    let mut budget = configured.max(limits::SYNC_MEMORY_MIN);
    if let Some(ram) = system_ram {
        budget = budget.min((ram / 2).max(limits::SYNC_MEMORY_MIN));
    }
    let two = 2 * GIB;
    if budget < two {
        (40 * MIB, 64 * MIB)
    } else if budget == two {
        (128 * MIB, 128 * MIB)
    } else {
        let extra = (budget - two) / 8;
        (128 * MIB + extra, 128 * MIB + extra)
    }
}

/// Notifications surfaced to the embedding application.
pub trait SyncObserver: Send + Sync {
    /// Sync progress in [0, 1].
    fn progress(&self, _done: u64, _total: u64) {}
    /// A bad event was encountered; polling is paused until the user chooses
    /// resync or logout (§12.2 step 5).
    fn bad_event(&self, _event_id: &str, _error: &Error) {}
    /// Sync finished.
    fn sync_finished(&self) {}
}

struct NoopObserver;
impl SyncObserver for NoopObserver {}

/// Owns the sync task and the event loop of one account.
pub struct Synchroniser {
    ctx: Arc<AccountContext>,
    observer: Arc<dyn SyncObserver>,
    sync_task: Mutex<Option<JoinHandle<()>>>,
    paused: watch::Sender<bool>,
}

impl Synchroniser {
    pub fn new(ctx: Arc<AccountContext>, observer: Option<Arc<dyn SyncObserver>>) -> Arc<Self> {
        let (tx, _) = watch::channel(false);
        Arc::new(Self {
            ctx,
            observer: observer.unwrap_or_else(|| Arc::new(NoopObserver)),
            sync_task: Mutex::new(None),
            paused: tx,
        })
    }

    /// Start background sync (if incomplete) and the event loop.
    pub fn start(self: &Arc<Self>) -> JoinHandle<()> {
        if !self.ctx.persisted().sync.is_complete() {
            self.start_sync();
        }
        let me = self.clone();
        tokio::spawn(async move { me.event_loop().await })
    }

    /// Resume polling after a bad event (the user chose resync or logout
    /// was handled elsewhere).
    pub fn resume(&self) {
        self.paused.send_replace(false);
    }

    /// Full resync requested by the user (§12.2 step 5).
    pub async fn resync(self: &Arc<Self>) -> Result<()> {
        let ev = self.ctx.persisted().last_event_id;
        self.reset_and_resync(ev).await?;
        self.resume();
        Ok(())
    }

    fn cancel_sync(&self) {
        if let Some(h) = self.sync_task.lock().expect("sync task lock").take() {
            h.abort();
        }
        self.ctx.set_sync_mode(false);
    }

    /// Spawn the initial-sync task, retrying with a 20 s cool-down.
    pub fn start_sync(self: &Arc<Self>) {
        self.cancel_sync();
        let me = self.clone();
        self.ctx.set_sync_mode(true);
        let h = tokio::spawn(async move {
            loop {
                match me.sync_once().await {
                    Ok(()) => break,
                    Err(e) => {
                        warn!("sync failed, retrying in 20 s: {e}");
                        tokio::time::sleep(limits::SYNC_RETRY_COOLDOWN).await;
                    }
                }
            }
            me.ctx.set_sync_mode(false);
            me.observer.sync_finished();
        });
        *self.sync_task.lock().expect("sync task lock") = Some(h);
    }

    async fn reset_and_resync(self: &Arc<Self>, start_event: Option<String>) -> Result<()> {
        self.cancel_sync();
        self.ctx.update_persisted(|p| {
            p.sync = Default::default();
            p.sync.start_event_id = start_event;
        })?;
        self.ctx.reload_labels().await?;
        self.ctx.rebuild_imap_sets()?;
        self.start_sync();
        Ok(())
    }

    // ---- initial sync ----------------------------------------------------------

    async fn sync_once(&self) -> Result<()> {
        let ctx = &self.ctx;
        // Step 1.
        let p = ctx.persisted();
        if p.sync.start_event_id.is_none() {
            let ev = p.last_event_id.clone();
            ctx.update_persisted(|p| p.sync.start_event_id = ev)?;
        }
        // Step 2.
        if !ctx.persisted().sync.labels_done {
            with_backoff(|| ctx.reload_labels()).await?;
            for set in ctx.imap_sets() {
                ctx.populate_mailboxes(&set)?;
            }
            ctx.update_persisted(|p| p.sync.labels_done = true)?;
        } else if ctx.labels().is_empty() {
            with_backoff(|| ctx.reload_labels()).await?;
        }
        // Step 3.
        let counts = with_backoff(|| ctx.client.get_message_counts()).await?;
        let total = counts
            .iter()
            .find(|c| c.label_id == label_id::ALL_MAIL)
            .map(|c| c.total.max(0) as u64)
            .unwrap_or(0);
        let total_units = total * 4;
        let mut done_units = 0u64;

        let (download_budget, _build_budget) = memory_budgets(ctx.settings.max_sync_memory, None);
        let max_par = ctx.settings.max_sync_parallelism.max(2);
        let mut parallel = max_par;

        // Steps 4–8.
        let mut cursor = ctx.persisted().sync.last_synced_message_id.clone();
        if !ctx.persisted().sync.messages_done {
            let mut pending: VecDeque<MessageMetadata> = VecDeque::new();
            loop {
                let filter = MessageFilter {
                    end_id: cursor.clone().unwrap_or_default(),
                    desc: true,
                    ..Default::default()
                };
                let mut page = with_backoff(|| {
                    ctx.client
                        .list_messages(&filter, 0, limits::SYNC_METADATA_PAGE)
                })
                .await?;
                if let (Some(c), Some(first)) = (&cursor, page.first())
                    && &first.id == c
                {
                    page.remove(0);
                }
                if page.is_empty() {
                    break;
                }
                cursor = page.last().map(|m| m.id.clone());
                done_units += page.len() as u64;
                self.observer.progress(done_units, total_units);
                pending.extend(page);

                // Step 5: batching.
                while !pending.is_empty() {
                    let mut batch = Vec::new();
                    let mut size = 0u64;
                    while let Some(m) = pending.front() {
                        let s = m.size.max(0) as u64;
                        if !batch.is_empty()
                            && (batch.len() >= limits::SYNC_BATCH_MESSAGES
                                || size + s >= download_budget)
                        {
                            break;
                        }
                        size += s;
                        batch.push(pending.pop_front().expect("front"));
                    }
                    let last_id = batch.last().map(|m| m.id.clone());
                    let had_throttle = self.download_and_apply(&batch, parallel).await?;
                    parallel = if had_throttle {
                        2
                    } else {
                        (parallel * 2).min(max_par)
                    };
                    done_units += 3 * batch.len() as u64;
                    self.observer.progress(done_units, total_units);
                    ctx.update_persisted(|p| p.sync.last_synced_message_id = last_id)?;
                }
            }
            ctx.update_persisted(|p| p.sync.messages_done = true)?;
        }
        // Step 9: rewind.
        ctx.update_persisted(|p| {
            if let Some(start) = p.sync.start_event_id.take() {
                p.last_event_id = Some(start);
            }
        })?;
        info!("initial sync complete");
        Ok(())
    }

    /// Download, build and apply one batch. Returns true if any request hit
    /// 429/5xx (used for adaptive concurrency).
    async fn download_and_apply(&self, batch: &[MessageMetadata], parallel: usize) -> Result<bool> {
        use futures::stream::{self, StreamExt};
        let ctx = &self.ctx;
        let throttled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ids: Vec<String> = batch.iter().map(|m| m.id.clone()).collect();
        let futs: Vec<_> = ids
            .into_iter()
            .map(|id| {
                let ctx = ctx.clone();
                let throttled = throttled.clone();
                async move { fetch_with_backoff(ctx, id, throttled).await }
            })
            .collect();
        let results: Vec<Result<Option<_>>> =
            stream::iter(futs).buffered(parallel.max(1)).collect().await;
        for r in results {
            let Some((msg, literal, failed)) = r? else {
                continue;
            };
            let Some(set) = ctx.imap_set_for_message(&msg.metadata.address_id) else {
                continue;
            };
            let lm = ctx.local_message(&msg, literal, failed);
            let wanted = ctx.wanted_mailboxes(&msg.metadata.label_ids);
            set.write().expect("set lock").upsert_message(lm, &wanted)?;
        }
        Ok(throttled.load(std::sync::atomic::Ordering::Relaxed))
    }

    // ---- event loop ------------------------------------------------------------------

    async fn event_loop(self: Arc<Self>) {
        let ctx = self.ctx.clone();
        if ctx.persisted().last_event_id.is_none() {
            match with_backoff(|| ctx.client.get_latest_event_id()).await {
                Ok(id) => {
                    let _ = ctx.update_persisted(|p| p.last_event_id = Some(id));
                }
                Err(e) => warn!("could not fetch latest event: {e}"),
            }
        }
        let mut conn = ctx.client.connectivity();
        let mut paused = self.paused.subscribe();
        loop {
            let wait = limits::EVENT_POLL_BASE + jitter(limits::EVENT_POLL_JITTER);
            tokio::time::sleep(wait).await;
            while *paused.borrow() {
                if paused.changed().await.is_err() {
                    return;
                }
            }
            if !*conn.borrow_and_update() {
                // Paused while disconnected; resume on the transition to up.
                while !*conn.borrow() {
                    if conn.changed().await.is_err() {
                        return;
                    }
                }
            }
            if let Err(e) = self.poll_once().await {
                debug!("event poll error: {e}");
            }
        }
    }

    /// One poll cycle (§12.2 steps 2–5).
    pub async fn poll_once(self: &Arc<Self>) -> Result<()> {
        let ctx = &self.ctx;
        let Some(last) = ctx.persisted().last_event_id else {
            return Ok(());
        };
        let events = with_backoff(|| ctx.client.get_events_chained(&last)).await?;
        for ev in events {
            match self.handle_event(&ev).await {
                Ok(()) => {
                    let id = ev.event_id.clone();
                    ctx.update_persisted(|p| p.last_event_id = Some(id))?;
                }
                Err(e) if e.is_transient() => return Err(e),
                Err(e) => {
                    warn!(event = %ev.event_id, "bad event: {e}");
                    self.observer.bad_event(&ev.event_id, &e);
                    self.paused.send_replace(true);
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Process one event: Refresh → User → Addresses → Labels → Messages.
    pub async fn handle_event(self: &Arc<Self>, ev: &Event) -> Result<()> {
        let ctx = &self.ctx;
        if ev.refresh & refresh_flag::MAIL != 0 {
            let user = ctx.client.get_user().await?;
            ctx.set_user(user);
            ctx.set_addresses(ctx.client.get_addresses().await?);
            self.reset_and_resync(Some(ev.event_id.clone())).await?;
            return Ok(());
        }
        if let Some(u) = &ev.user {
            ctx.set_user(u.clone());
            if let Err(e) = ctx.reunlock_user_ring() {
                warn!("could not re-unlock user keys after user event: {e}");
            }
        }
        if let Some(ms) = &ev.mail_settings {
            ctx.set_mail_settings(ms.clone());
        }
        if !ev.addresses.is_empty() {
            self.handle_addresses(ev).await?;
        }
        for le in &ev.labels {
            self.handle_label(le.id.as_str(), le.action, le.label.as_ref())
                .await?;
        }
        for me in &ev.messages {
            self.handle_message(&me.id, me.action, me.message.as_ref())
                .await?;
        }
        Ok(())
    }

    async fn handle_addresses(&self, ev: &Event) -> Result<()> {
        let ctx = &self.ctx;
        let before = ctx.addresses();
        let primary_before = ctx.primary_address().map(|a| a.id);
        ctx.set_addresses(ctx.client.get_addresses().await?);
        match ctx.mode() {
            AddressMode::Combined => {
                if ctx.primary_address().map(|a| a.id) != primary_before {
                    ctx.rebind_combined();
                }
            }
            AddressMode::Split => {
                for ae in &ev.addresses {
                    let was = before
                        .iter()
                        .find(|a| a.id == ae.id)
                        .map(|a| a.is_enabled());
                    let now = ctx.address(&ae.id).map(|a| a.is_enabled());
                    match (ae.action, was, now) {
                        (event_action::DELETE, Some(true), _) => ctx.remove_imap_set(&ae.id),
                        (event_action::CREATE, _, Some(true)) => ctx.add_imap_set(&ae.id)?,
                        (_, Some(false) | None, Some(true)) => ctx.add_imap_set(&ae.id)?,
                        (_, Some(true), Some(false)) => ctx.remove_imap_set(&ae.id),
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_label(&self, id: &str, action: i64, label: Option<&Label>) -> Result<()> {
        let ctx = &self.ctx;
        match action {
            event_action::DELETE => {
                ctx.delete_label_mailbox(id);
                ctx.remove_label(id);
            }
            event_action::CREATE => {
                if let Some(l) = label.filter(|l| l.is_wanted()) {
                    ctx.put_label(l.clone());
                    ctx.apply_label(l)?;
                }
            }
            _ => {
                let kinds = [label_type::SYSTEM, label_type::FOLDER, label_type::LABEL];
                let fresh = match ctx.client.get_label(id, &kinds).await {
                    Ok(l) => l,
                    Err(Error::NotFound(_)) => return Ok(()),
                    Err(e) if is_unprocessable(&e) => return Ok(()),
                    Err(e) => return Err(e),
                };
                if !fresh.is_wanted() {
                    return Ok(());
                }
                ctx.put_label(fresh.clone());
                ctx.apply_label(&fresh)?;
                // Descendants' paths changed too.
                let labels = ctx.labels();
                let mut stack = vec![fresh.id.clone()];
                while let Some(pid) = stack.pop() {
                    for child in labels.values().filter(|l| l.parent_id == pid) {
                        let updated = ctx
                            .client
                            .get_label(&child.id, &kinds)
                            .await
                            .unwrap_or_else(|_| child.clone());
                        ctx.put_label(updated.clone());
                        ctx.apply_label(&updated)?;
                        stack.push(child.id.clone());
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_message(
        &self,
        id: &str,
        action: i64,
        meta: Option<&MessageMetadata>,
    ) -> Result<()> {
        let ctx = &self.ctx;
        let sync_mode = ctx.in_sync_mode();
        match action {
            event_action::DELETE => {
                for set in ctx.imap_sets() {
                    set.write().expect("set lock").remove_message(id);
                }
                Ok(())
            }
            event_action::CREATE => self.create_message(id, false).await,
            _ => {
                let Some(meta) = meta else {
                    return self.create_message(id, true).await;
                };
                let full_replace = (meta.is_draft() || meta.is_sent())
                    && (action == event_action::UPDATE || sync_mode);
                if full_replace {
                    return self.create_message(id, true).await;
                }
                let Some(set) = ctx.imap_set_for_message(&meta.address_id) else {
                    return Ok(());
                };
                let known = set.read().expect("set lock").message(id).is_some();
                if !known {
                    return self.create_message(id, false).await;
                }
                let wanted = ctx.wanted_mailboxes(&meta.label_ids);
                let mut s = set.write().expect("set lock");
                let old = s.message(id).map(|m| m.flags.clone()).unwrap_or_default();
                if let Some(m) = s.message_mut(id) {
                    m.label_ids = meta.label_ids.clone();
                }
                s.set_flags(id, MessageFlags::from_metadata(meta).merge_local(&old));
                s.set_membership(id, &wanted)?;
                Ok(())
            }
        }
    }

    async fn create_message(&self, id: &str, replace: bool) -> Result<()> {
        let ctx = &self.ctx;
        let Some((msg, literal, failed)) = ctx.fetch_and_build(id).await? else {
            return Ok(());
        };
        let unknown = ctx.unknown_labels(&msg.metadata.label_ids);
        if !unknown.is_empty() && !ctx.in_sync_mode() {
            return Err(Error::Invalid(format!(
                "message {id} references unknown labels {unknown:?}"
            )));
        }
        let set = match ctx.imap_set_for_message(&msg.metadata.address_id) {
            Some(s) => s,
            None => return Ok(()),
        };
        let lm = ctx.local_message(&msg, literal, failed);
        let wanted = ctx.wanted_mailboxes(&msg.metadata.label_ids);
        let mut s = set.write().expect("set lock");
        if replace && s.message(id).is_some() {
            s.replace_message(lm, &wanted)
        } else {
            s.upsert_message(lm, &wanted)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budgets() {
        assert_eq!(memory_budgets(GIB, None), (40 * MIB, 64 * MIB));
        assert_eq!(memory_budgets(2 * GIB, None), (128 * MIB, 128 * MIB));
        assert_eq!(
            memory_budgets(10 * GIB, None),
            (128 * MIB + GIB, 128 * MIB + GIB)
        );
        // Clamped to half of RAM (4 GiB RAM → 2 GiB).
        assert_eq!(
            memory_budgets(10 * GIB, Some(4 * GIB)),
            (128 * MIB, 128 * MIB)
        );
        // Clamped up to 800 MiB minimum.
        assert_eq!(memory_budgets(0, None), (40 * MIB, 64 * MIB));
    }
}
