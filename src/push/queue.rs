//! Notification quick actions (§14.6): the immediate attempt, the durable
//! per-account outgoing-action queue, local application, deferred remote
//! application, revert and rebase.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::api::ApiClient;
use crate::api::backoff::Backoff;
use crate::api::push::{ARCHIVE_LABEL, Delivery, TRASH_LABEL};
use crate::api::types::{Label, label_id, label_type};
use crate::error::{Error, Result};
use crate::gateway::AccountContext;
use crate::imap::store::ImapSet;

/// Current queue record format. Version 1 records lack `remote_pending`.
pub const QUEUE_RECORD_VERSION: u32 = 2;
/// Quick actions are queued at the highest priority (§14.6.2 step 4).
pub const PRIORITY_HIGHEST: i32 = i32::MAX;
/// Cap of the immediate attempt's deadline (§14.6.2 step 2).
pub const QUICK_ACTION_DEADLINE_CAP: Duration = Duration::from_secs(30);

/// A notification quick action (§14.6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuickAction {
    MarkRead,
    MoveToArchive,
    MoveToTrash,
}

impl QuickAction {
    /// The destination system label of a move.
    pub fn target_label(self) -> Option<&'static str> {
        match self {
            QuickAction::MarkRead => None,
            QuickAction::MoveToArchive => Some(ARCHIVE_LABEL),
            QuickAction::MoveToTrash => Some(TRASH_LABEL),
        }
    }

    /// Send the remote request (§14.6.1).
    pub async fn send(
        self,
        client: &ApiClient,
        message_id: &str,
        delivery: Delivery,
    ) -> Result<()> {
        match self.target_label() {
            None => client.notification_mark_read(message_id, delivery).await,
            Some(label) => client.notification_move(message_id, label, delivery).await,
        }
    }
}

/// The pre-action local state, recorded so that a local mutation can be
/// reverted (§14.6.2 steps 5 and 7).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalInverse {
    pub label_ids: Vec<String>,
    pub seen: bool,
}

/// Progress of a record's local phase.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalState {
    /// Not processed locally yet.
    #[default]
    Pending,
    /// Applied to the local copy; holds the inverse.
    Applied(LocalInverse),
    /// The message was not in the local store; nothing was changed.
    NotPresent,
}

fn default_version() -> u32 {
    1
}

fn remote_pending_default() -> bool {
    true
}

/// One record of the persistent outgoing-action queue. Versioned: a record
/// written by an earlier format without `remote_pending` reads it as
/// `true`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedAction {
    #[serde(default = "default_version")]
    pub version: u32,
    pub id: String,
    #[serde(default)]
    pub priority: i32,
    pub action: QuickAction,
    pub message_id: String,
    /// The remote request must still be sent (the immediate attempt failed).
    #[serde(default = "remote_pending_default")]
    pub remote_pending: bool,
    #[serde(default)]
    pub local: LocalState,
}

impl QueuedAction {
    pub fn new(action: QuickAction, message_id: &str, remote_pending: bool) -> Self {
        Self {
            version: QUEUE_RECORD_VERSION,
            id: uuid::Uuid::new_v4().to_string(),
            priority: PRIORITY_HIGHEST,
            action,
            message_id: message_id.to_string(),
            remote_pending,
            local: LocalState::Pending,
        }
    }

    /// Nothing is left to do for this record.
    fn is_finished(&self) -> bool {
        !self.remote_pending && self.local != LocalState::Pending
    }
}

/// `min(T − 1 s, 30 s)`, floored at zero (§14.6.2 step 2).
pub fn quick_action_deadline(remaining: Duration) -> Duration {
    remaining
        .saturating_sub(Duration::from_secs(1))
        .min(QUICK_ACTION_DEADLINE_CAP)
}

/// Insert keeping descending priority, FIFO within a priority.
fn insert_by_priority(queue: &mut Vec<QueuedAction>, rec: QueuedAction) {
    let pos = queue
        .iter()
        .position(|r| r.priority < rec.priority)
        .unwrap_or(queue.len());
    queue.insert(pos, rec);
}

/// Labels a move removes: the exclusive system locations and every folder.
fn is_exclusive(id: &str, labels: &HashMap<String, Label>) -> bool {
    matches!(
        id,
        label_id::INBOX | label_id::ARCHIVE | label_id::TRASH | label_id::SPAM
    ) || labels.get(id).is_some_and(|l| l.kind == label_type::FOLDER)
}

/// Label IDs after moving to `target`.
pub fn moved_label_ids(
    current: &[String],
    target: &str,
    labels: &HashMap<String, Label>,
) -> Vec<String> {
    let mut out: Vec<String> = current
        .iter()
        .filter(|id| !is_exclusive(id, labels))
        .cloned()
        .collect();
    out.push(target.to_string());
    if !out.iter().any(|l| l == label_id::ALL_MAIL) {
        out.push(label_id::ALL_MAIL.to_string());
    }
    out
}

/// Mailboxes (wanted labels) for a set of label IDs (§11.6).
pub(crate) fn wanted(labels: &HashMap<String, Label>, ids: &[String]) -> Vec<String> {
    ids.iter()
        .filter(|id| labels.get(*id).is_some_and(Label::is_wanted))
        .cloned()
        .collect()
}

/// Apply `action` to the local copy of `message_id` in `set`, returning the
/// inverse, or `None` if the message is not there.
pub(crate) fn apply_in_set(
    set: &mut ImapSet,
    action: QuickAction,
    message_id: &str,
    labels: &HashMap<String, Label>,
) -> Result<Option<LocalInverse>> {
    let Some(m) = set.message(message_id) else {
        return Ok(None);
    };
    let inverse = LocalInverse {
        label_ids: m.label_ids.clone(),
        seen: m.flags.seen,
    };
    match action.target_label() {
        None => {
            let mut f = m.flags.clone();
            f.seen = true;
            set.set_flags(message_id, f);
        }
        Some(target) => {
            let new = moved_label_ids(&inverse.label_ids, target, labels);
            if let Some(m) = set.message_mut(message_id) {
                m.label_ids = new.clone();
            }
            set.set_membership(message_id, &wanted(labels, &new))?;
        }
    }
    Ok(Some(inverse))
}

fn revert_in_set(
    set: &mut ImapSet,
    message_id: &str,
    inv: &LocalInverse,
    labels: &HashMap<String, Label>,
) -> Result<()> {
    let Some(m) = set.message(message_id) else {
        return Ok(());
    };
    let mut f = m.flags.clone();
    f.seen = inv.seen;
    set.set_flags(message_id, f);
    if let Some(m) = set.message_mut(message_id) {
        m.label_ids = inv.label_ids.clone();
    }
    set.set_membership(message_id, &wanted(labels, &inv.label_ids))
}

/// Re-apply every pending action touching `message_id` to its freshly
/// stored copy (§14.7.1 step 4c). Returns the new local states by record
/// ID; the caller persists them with [`save_local_states`].
pub(crate) fn rebase_in_set(
    set: &mut ImapSet,
    message_id: &str,
    queue: &[QueuedAction],
    labels: &HashMap<String, Label>,
) -> Result<Vec<(String, LocalState)>> {
    let mut out = Vec::new();
    for rec in queue
        .iter()
        .filter(|r| r.remote_pending && r.message_id == message_id)
    {
        if let Some(inv) = apply_in_set(set, rec.action, message_id, labels)? {
            out.push((rec.id.clone(), LocalState::Applied(inv)));
        }
    }
    Ok(out)
}

/// Record new local states and drop records that are finished.
pub(crate) fn save_local_states(
    ctx: &AccountContext,
    states: Vec<(String, LocalState)>,
) -> Result<()> {
    if states.is_empty() {
        return Ok(());
    }
    ctx.update_persisted(|p| {
        for (id, st) in states {
            if let Some(r) = p.action_queue.iter_mut().find(|r| r.id == id) {
                r.local = st;
            }
        }
        p.action_queue.retain(|r| !r.is_finished());
    })
}

/// The local phase (§14.6.2 step 5) for every record not yet processed.
pub fn apply_local(ctx: &AccountContext) -> Result<()> {
    let pending: Vec<QueuedAction> = ctx
        .persisted()
        .action_queue
        .into_iter()
        .filter(|r| r.local == LocalState::Pending)
        .collect();
    if pending.is_empty() {
        return Ok(());
    }
    let labels = ctx.labels();
    let mut states = Vec::new();
    for rec in pending {
        let mut state = LocalState::NotPresent;
        for set in ctx.imap_sets() {
            let mut s = set.write().expect("set lock");
            if let Some(inv) = apply_in_set(&mut s, rec.action, &rec.message_id, &labels)? {
                state = LocalState::Applied(inv);
                break;
            }
        }
        states.push((rec.id, state));
    }
    ctx.update_persisted(|p| {
        for (id, st) in states {
            if let Some(r) = p.action_queue.iter_mut().find(|r| r.id == id) {
                r.local = st;
            }
        }
        p.action_queue.retain(|r| !r.is_finished());
    })
}

fn revert(ctx: &AccountContext, rec: &QueuedAction) {
    let LocalState::Applied(inv) = &rec.local else {
        return;
    };
    let labels = ctx.labels();
    for set in ctx.imap_sets() {
        let mut s = set.write().expect("set lock");
        if s.message(&rec.message_id).is_some() {
            if let Err(e) = revert_in_set(&mut s, &rec.message_id, inv, &labels) {
                warn!("could not revert a failed quick action locally: {e}");
            }
            return;
        }
    }
}

/// Durable enqueue (§14.6.2 step 4), then the local phase, then (if needed)
/// the deferred remote phase in the background.
pub fn enqueue(
    ctx: &Arc<AccountContext>,
    action: QuickAction,
    message_id: &str,
    remote_pending: bool,
) -> Result<()> {
    let rec = QueuedAction::new(action, message_id, remote_pending);
    ctx.update_persisted(|p| insert_by_priority(&mut p.action_queue, rec))?;
    apply_local(ctx)?;
    if ctx
        .persisted()
        .action_queue
        .iter()
        .any(|r| r.remote_pending)
    {
        spawn_remote(ctx.clone());
    }
    Ok(())
}

/// Start the deferred remote phase in the background.
pub fn spawn_remote(ctx: Arc<AccountContext>) {
    tokio::spawn(async move {
        if let Err(e) = run_remote(&ctx).await {
            debug!("outgoing-action queue stopped: {e}");
        }
    });
}

fn is_retryable(e: &Error) -> bool {
    e.is_transient() || e.is_backoff_retryable()
}

/// The deferred remote phase (§14.6.2 steps 6–7): send every record whose
/// remote request is still pending, in priority order, with the normal
/// retry policy and no deadline. Transient failures back off and retry;
/// a permanent failure reverts the local mutation and drops the record.
/// Returns early (keeping the records) if the session is gone.
pub async fn run_remote(ctx: &AccountContext) -> Result<()> {
    let _runner = ctx.push.queue_runner.lock().await;
    let mut backoff = Backoff::new();
    loop {
        if !ctx.persisted().is_signed_in() {
            return Err(Error::Deauthenticated);
        }
        let Some(rec) = ctx
            .persisted()
            .action_queue
            .into_iter()
            .find(|r| r.remote_pending)
        else {
            return Ok(());
        };
        match rec
            .action
            .send(&ctx.client, &rec.message_id, Delivery::Normal)
            .await
        {
            Ok(()) => {
                backoff.reset();
                ctx.update_persisted(|p| p.action_queue.retain(|r| r.id != rec.id))?;
            }
            Err(Error::Deauthenticated) => return Err(Error::Deauthenticated),
            Err(e) if is_retryable(&e) => {
                let d = backoff.next_delay();
                debug!(?d, "quick action will be retried: {e}");
                tokio::time::sleep(d).await;
            }
            Err(e) => {
                warn!(action = ?rec.action, "quick action failed permanently: {e}");
                revert(ctx, &rec);
                ctx.update_persisted(|p| p.action_queue.retain(|r| r.id != rec.id))?;
            }
        }
    }
}

/// The execution procedure (§14.6.2). `ctx` is the Account resolved from
/// the notification's UID; `remaining` is the background-execution time
/// the operating system reports, if known.
pub async fn execute(
    ctx: Option<&Arc<AccountContext>>,
    action: QuickAction,
    message_id: &str,
    remaining: Option<Duration>,
) -> Result<()> {
    // Step 1: no initialised session → success without effect.
    let Some(ctx) = ctx.filter(|c| c.persisted().is_signed_in()) else {
        return Ok(());
    };
    // Steps 2–3.
    let deadline = remaining.map(quick_action_deadline);
    let sent = match action
        .send(&ctx.client, message_id, Delivery::Immediate { deadline })
        .await
    {
        Ok(()) => true,
        Err(e) => {
            debug!(?action, "immediate quick action failed; deferring: {e}");
            false
        }
    };
    // Steps 4–6.
    enqueue(ctx, action, message_id, !sent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imap::mailbox::MailboxKind;
    use crate::imap::mailbox::UidValidityGenerator;
    use crate::imap::store::LocalMessage;

    fn labels() -> HashMap<String, Label> {
        let mut m = HashMap::new();
        for (id, kind) in [
            ("0", 4),
            ("3", 4),
            ("5", 4),
            ("6", 4),
            ("10", 4),
            ("f1", 3),
            ("l1", 1),
        ] {
            m.insert(
                id.to_string(),
                Label {
                    id: id.into(),
                    name: id.into(),
                    path: id.into(),
                    kind,
                    ..Default::default()
                },
            );
        }
        m
    }

    use crate::push::test_support;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn mailboxes(ctx: &AccountContext) -> Vec<String> {
        let set = ctx.imap_set_for_message("a1").unwrap();
        let mut v = set.read().unwrap().mailboxes_of("m1");
        v.sort();
        v
    }

    async fn wait_queue_empty(ctx: &AccountContext) {
        for _ in 0..300 {
            if ctx.persisted().action_queue.is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("queue not drained: {:?}", ctx.persisted().action_queue);
    }

    #[tokio::test]
    async fn failed_immediate_attempt_is_queued_then_sent() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c2 = calls.clone();
        let stub = test_support::start(Arc::new(move |_| {
            if c2.fetch_add(1, Ordering::SeqCst) == 0 {
                (409, r#"{"Code":2500,"Error":"busy"}"#.into())
            } else {
                (
                    200,
                    r#"{"Code":1001,"Responses":[{"ID":"m1","Response":{"Code":1000}}]}"#.into(),
                )
            }
        }))
        .await;
        let ctx = test_support::account(&stub.base).await;
        execute(
            Some(&ctx),
            QuickAction::MoveToTrash,
            "m1",
            Some(Duration::from_secs(20)),
        )
        .await
        .unwrap();
        // Applied locally right away.
        assert_eq!(mailboxes(&ctx), ["3", "5"]);
        wait_queue_empty(&ctx).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(mailboxes(&ctx), ["3", "5"]);
    }

    #[tokio::test]
    async fn successful_immediate_attempt_is_not_resent() {
        let stub = test_support::start(Arc::new(|_| {
            (
                200,
                r#"{"Code":1001,"Responses":[{"ID":"m1","Response":{"Code":1000}}]}"#.into(),
            )
        }))
        .await;
        let ctx = test_support::account(&stub.base).await;
        execute(Some(&ctx), QuickAction::MarkRead, "m1", None)
            .await
            .unwrap();
        assert!(ctx.persisted().action_queue.is_empty());
        let set = ctx.imap_set_for_message("a1").unwrap();
        assert!(set.read().unwrap().message("m1").unwrap().flags.seen);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(stub.seen.lock().unwrap().len(), 1);
        // Signed-out account: success without effect.
        execute(None, QuickAction::MarkRead, "m1", None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn permanent_failure_reverts() {
        let stub =
            test_support::start(Arc::new(|_| (422, r#"{"Code":2501,"Error":"no"}"#.into()))).await;
        let ctx = test_support::account(&stub.base).await;
        execute(Some(&ctx), QuickAction::MoveToArchive, "m1", None)
            .await
            .unwrap();
        wait_queue_empty(&ctx).await;
        assert_eq!(mailboxes(&ctx), ["0", "5"]);
        assert_eq!(stub.seen.lock().unwrap().len(), 2);
    }

    #[test]
    fn deadline() {
        assert_eq!(
            quick_action_deadline(Duration::from_secs(10)),
            Duration::from_secs(9)
        );
        assert_eq!(
            quick_action_deadline(Duration::from_secs(100)),
            Duration::from_secs(30)
        );
        assert_eq!(
            quick_action_deadline(Duration::from_millis(400)),
            Duration::ZERO
        );
    }

    #[test]
    fn v1_records_default_to_remote_pending() {
        let r: QueuedAction =
            serde_json::from_str(r#"{"id":"r","action":"MoveToTrash","message_id":"m"}"#).unwrap();
        assert_eq!(r.version, 1);
        assert!(r.remote_pending);
        assert_eq!(r.local, LocalState::Pending);
        let r2: QueuedAction = serde_json::from_value(
            serde_json::to_value(QueuedAction::new(QuickAction::MarkRead, "m", false)).unwrap(),
        )
        .unwrap();
        assert_eq!(r2.version, QUEUE_RECORD_VERSION);
        assert!(!r2.remote_pending);
    }

    #[test]
    fn priority_insertion() {
        let mut q = vec![];
        let mut low = QueuedAction::new(QuickAction::MarkRead, "a", true);
        low.priority = 0;
        insert_by_priority(&mut q, low);
        insert_by_priority(&mut q, QueuedAction::new(QuickAction::MarkRead, "b", true));
        insert_by_priority(&mut q, QueuedAction::new(QuickAction::MarkRead, "c", true));
        let ids: Vec<&str> = q.iter().map(|r| r.message_id.as_str()).collect();
        assert_eq!(ids, ["b", "c", "a"]);
    }

    #[test]
    fn move_semantics() {
        let l = labels();
        let cur: Vec<String> = ["0", "5", "10", "l1", "f1"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut got = moved_label_ids(&cur, "6", &l);
        got.sort();
        assert_eq!(got, ["10", "5", "6", "l1"]);
    }

    #[test]
    fn apply_and_revert_locally() {
        let l = labels();
        let mut set = ImapSet::new("a", Arc::new(UidValidityGenerator::new()));
        for id in ["0", "3", "5", "6"] {
            set.create_mailbox(id, vec![id.into()], MailboxKind::System)
                .unwrap();
        }
        let mut m = LocalMessage::new("m");
        m.label_ids = vec!["0".into(), "5".into()];
        set.upsert_message(m, &["0".to_string(), "5".to_string()])
            .unwrap();

        let inv = apply_in_set(&mut set, QuickAction::MoveToTrash, "m", &l)
            .unwrap()
            .unwrap();
        assert_eq!(inv.label_ids, ["0", "5"]);
        let mut mbs = set.mailboxes_of("m");
        mbs.sort();
        assert_eq!(mbs, ["3", "5"]);

        let inv2 = apply_in_set(&mut set, QuickAction::MarkRead, "m", &l)
            .unwrap()
            .unwrap();
        assert!(!inv2.seen);
        assert!(set.message("m").unwrap().flags.seen);

        revert_in_set(&mut set, "m", &inv, &l).unwrap();
        let mut mbs = set.mailboxes_of("m");
        mbs.sort();
        assert_eq!(mbs, ["0", "5"]);
        assert!(!set.message("m").unwrap().flags.seen);

        assert!(
            apply_in_set(&mut set, QuickAction::MarkRead, "missing", &l)
                .unwrap()
                .is_none()
        );
    }
}
