//! Opening a notification (§14.7): fresh message resolution and
//! notification-originated conversation opening.

use std::collections::HashMap;
use std::sync::Arc;

use tracing::warn;

use super::queue::{rebase_in_set, save_local_states, wanted};
use super::registration::Connectivity;
use crate::account::AddressMode;
use crate::api::types::{Conversation, Label, MessageMetadata, message_flag};
use crate::error::{Error, Result};
use crate::gateway::AccountContext;
use crate::imap::store::{ImapSet, LocalMessage, MessageFlags};
use crate::util::now_unix;

/// A message as stored locally after resolution: the server metadata with
/// the rebased pending local actions applied, and the local copy (absent if
/// the message belongs to no local mailbox set).
#[derive(Debug, Clone)]
pub struct OpenedMessage {
    pub metadata: MessageMetadata,
    pub local: Option<LocalMessage>,
}

/// A conversation opened from a notification (§14.7.2).
#[derive(Debug, Clone)]
pub struct OpenedConversation {
    pub conversation: Conversation,
    /// The messages carrying the label the conversation was opened from,
    /// oldest first.
    pub messages: Vec<OpenedMessage>,
    /// The message to focus (§14.7.2 step 7).
    pub focused_message_id: Option<String>,
}

/// The label's focus rule: the oldest message in the most recent run of
/// consecutive unread messages, else the latest message. `messages` must be
/// ordered oldest first.
pub fn focused_message(messages: &[MessageMetadata]) -> Option<&MessageMetadata> {
    match messages.iter().rposition(|m| m.unread) {
        Some(end) => {
            let mut start = end;
            while start > 0 && messages[start - 1].unread {
                start -= 1;
            }
            messages.get(start)
        }
        None => messages.last(),
    }
}

/// Fetch and store any objects the messages reference that are missing
/// locally: labels/folders, the owning Address and (optionally) the
/// conversation (§14.7.1 step 3).
async fn ensure_dependencies(
    ctx: &AccountContext,
    metas: &[MessageMetadata],
    fetch_conversations: bool,
) -> Result<()> {
    let label_ids: Vec<String> = metas.iter().flat_map(|m| m.label_ids.clone()).collect();
    if !ctx.unknown_labels(&label_ids).is_empty() {
        ctx.reload_labels().await?;
        for id in &label_ids {
            if let Some(l) = ctx.label(id).filter(Label::is_wanted) {
                ctx.apply_label(&l)?;
            }
        }
    }
    if metas
        .iter()
        .any(|m| !m.address_id.is_empty() && ctx.address(&m.address_id).is_none())
    {
        ctx.set_addresses(ctx.client.get_addresses().await?);
        if ctx.mode() == AddressMode::Split {
            for m in metas {
                if ctx.imap_set(&m.address_id).is_none()
                    && ctx.address(&m.address_id).is_some_and(|a| a.is_enabled())
                {
                    ctx.add_imap_set(&m.address_id)?;
                }
            }
        }
    }
    if fetch_conversations {
        for m in metas {
            let cid = &m.conversation_id;
            if !cid.is_empty()
                && ctx.push.conversation(cid).is_none()
                && let Some((conv, _)) = ctx.client.get_conversation(cid).await?
            {
                ctx.push.put_conversation(conv);
            }
        }
    }
    Ok(())
}

/// Whether the server copy may overwrite the stored copy (§14.7.1 step 4a):
/// not if the message is a draft open in a local composer that has been
/// neither sent nor scheduled since.
fn server_copy_applies(ctx: &AccountContext, set: &ImapSet, meta: &MessageMetadata) -> bool {
    let sent_or_scheduled = !meta.is_draft() || meta.flags & message_flag::SCHEDULED_SEND != 0;
    !(set.message(&meta.id).is_some() && ctx.push.is_draft_open(&meta.id) && !sent_or_scheduled)
}

/// New local states of queue records, by record ID.
type StateUpdates = Vec<(String, super::queue::LocalState)>;

fn store_in_set(
    ctx: &AccountContext,
    set: &mut ImapSet,
    meta: &MessageMetadata,
    labels: &HashMap<String, Label>,
    queue: &[super::queue::QueuedAction],
) -> Result<(StateUpdates, Option<LocalMessage>)> {
    if server_copy_applies(ctx, set, meta) {
        let old_flags = set.message(&meta.id).map(|m| m.flags.clone());
        let mut lm = LocalMessage::new(&meta.id);
        lm.flags = match &old_flags {
            Some(old) => MessageFlags::from_metadata(meta).merge_local(old),
            None => MessageFlags::from_metadata(meta),
        };
        lm.label_ids = meta.label_ids.clone();
        lm.address_id = meta.address_id.clone();
        lm.internal_date = if meta.time > 0 { meta.time } else { now_unix() };
        // The body is fetched and built on demand (§14.7.2).
        set.upsert_message(lm, &wanted(labels, &meta.label_ids))?;
        if meta.is_draft()
            && let Some(m) = set.message_mut(&meta.id)
        {
            // A draft's content may have changed: rebuild on next FETCH.
            m.literal = None;
        }
    }
    let states = rebase_in_set(set, &meta.id, queue, labels)?;
    Ok((states, set.message(&meta.id).cloned()))
}

/// Store server metadata and rebase pending local actions (§14.7.1 step 4),
/// returning the re-read copies (step 5).
fn store_messages(ctx: &AccountContext, metas: Vec<MessageMetadata>) -> Result<Vec<OpenedMessage>> {
    let labels = ctx.labels();
    let queue = ctx.persisted().action_queue;
    let mut out = Vec::with_capacity(metas.len());
    let mut states = Vec::new();
    for mut meta in metas {
        let local = match ctx.imap_set_for_message(&meta.address_id) {
            Some(set) => {
                let mut s = set.write().expect("set lock");
                let (st, local) = store_in_set(ctx, &mut s, &meta, &labels, &queue)?;
                states.extend(st);
                local
            }
            None => None,
        };
        if let Some(l) = &local {
            meta.label_ids = l.label_ids.clone();
            meta.unread = !l.flags.seen;
        }
        out.push(OpenedMessage {
            metadata: meta,
            local,
        });
    }
    save_local_states(ctx, states)?;
    Ok(out)
}

/// Resolve a notification's message from fresh server state (§14.7.1).
/// Fails with [`Error::NotFound`] if the Service no longer has it.
pub async fn resolve_message(ctx: &Arc<AccountContext>, message_id: &str) -> Result<OpenedMessage> {
    let meta = ctx
        .client
        .get_message_metadata(message_id)
        .await?
        .ok_or_else(|| Error::NotFound("message not found on server".into()))?;
    ensure_dependencies(ctx, std::slice::from_ref(&meta), true).await?;
    store_messages(ctx, vec![meta])?
        .pop()
        .ok_or_else(|| Error::NotFound("message not found on server".into()))
}

/// Open a conversation from a notification (§14.7.2). Returns `Ok(None)` if
/// the conversation was deleted (nothing to display, not an error).
/// `snooze_reminder` marks the conversation read in `label_id`.
pub async fn open_conversation(
    ctx: &Arc<AccountContext>,
    connectivity: &dyn Connectivity,
    conversation_id: &str,
    label_id: &str,
    snooze_reminder: bool,
) -> Result<Option<OpenedConversation>> {
    if !connectivity.is_online() {
        return Err(Error::Network(
            "offline: cannot open a notification without fresh state".into(),
        ));
    }
    let Some((conversation, metas)) = ctx.client.get_conversation(conversation_id).await? else {
        return Ok(None);
    };
    ensure_dependencies(ctx, &metas, false).await?;
    ctx.push.put_conversation(conversation.clone());
    let stored = store_messages(ctx, metas)?;
    if !conversation.has_label(label_id) {
        return Err(Error::NotFound(format!(
            "conversation is no longer in label {label_id}"
        )));
    }
    let mut messages: Vec<OpenedMessage> = stored
        .into_iter()
        .filter(|m| m.metadata.has_label(label_id))
        .collect();
    messages
        .sort_by(|a, b| (a.metadata.time, &a.metadata.id).cmp(&(b.metadata.time, &b.metadata.id)));
    let metas: Vec<MessageMetadata> = messages.iter().map(|m| m.metadata.clone()).collect();
    let focused_message_id = focused_message(&metas).map(|m| m.id.clone());

    if snooze_reminder {
        let unread: Vec<String> = messages
            .iter()
            .filter(|m| m.metadata.unread)
            .map(|m| m.metadata.id.clone())
            .collect();
        if !unread.is_empty() {
            match ctx.client.mark_read(&unread).await {
                Ok(()) => {
                    for m in messages.iter_mut().filter(|m| m.metadata.unread) {
                        m.metadata.unread = false;
                        if let Some(set) = ctx.imap_set_for_message(&m.metadata.address_id) {
                            let mut s = set.write().expect("set lock");
                            if let Some(cur) = s.message(&m.metadata.id) {
                                let mut f = cur.flags.clone();
                                f.seen = true;
                                s.set_flags(&m.metadata.id, f);
                            }
                            m.local = s.message(&m.metadata.id).cloned();
                        }
                    }
                }
                Err(e) => warn!("could not mark snoozed conversation read: {e}"),
            }
        }
    }

    Ok(Some(OpenedConversation {
        conversation,
        messages,
        focused_message_id,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(id: &str, unread: bool) -> MessageMetadata {
        MessageMetadata {
            id: id.into(),
            unread,
            ..Default::default()
        }
    }

    use crate::push::queue::{QueuedAction, QuickAction};
    use crate::push::test_support;
    use futures::future::BoxFuture;

    struct Net(bool);
    impl Connectivity for Net {
        fn is_online(&self) -> bool {
            self.0
        }
        fn wait_online(&self) -> BoxFuture<'_, ()> {
            Box::pin(async {})
        }
    }

    const CONV: &str = r#"{"Code":1000,
        "Conversation":{"ID":"c1","Labels":[{"ID":"0"},{"ID":"5"}]},
        "Messages":[
          {"ID":"m1","AddressID":"a1","ConversationID":"c1","LabelIDs":["0","5"],"Time":1,"Unread":0,"Flags":1},
          {"ID":"m2","AddressID":"a1","ConversationID":"c1","LabelIDs":["0","5"],"Time":2,"Unread":1,"Flags":1},
          {"ID":"m3","AddressID":"a1","ConversationID":"c1","LabelIDs":["0","5"],"Time":3,"Unread":1,"Flags":1}]}"#;

    fn responder(s: &test_support::Seen) -> (u16, String) {
        match s.path.as_str() {
            "/mail/v4/messages?ID%5B0%5D=m2&Page=0" => (200, r#"{"Messages":[{"ID":"m2","AddressID":"a1",
                "ConversationID":"c1","LabelIDs":["0","5"],"Time":2,"Unread":1,"Flags":1}],"Total":1}"#.into()),
            "/mail/v4/messages?ID%5B0%5D=gone&Page=0" => (200, r#"{"Messages":[],"Total":0}"#.into()),
            "/mail/v4/conversations/c1" => (200, CONV.into()),
            "/mail/v4/messages/read" => (200, r#"{"Responses":[]}"#.into()),
            _ => (422, r#"{"Code":20052,"Error":"gone"}"#.into()),
        }
    }

    #[tokio::test]
    async fn resolve_rebases_pending_actions() {
        let stub = test_support::start(Arc::new(responder)).await;
        let ctx = test_support::account(&stub.base).await;
        ctx.update_persisted(|p| {
            p.action_queue
                .push(QueuedAction::new(QuickAction::MarkRead, "m2", true))
        })
        .unwrap();
        let m = resolve_message(&ctx, "m2").await.unwrap();
        assert!(!m.metadata.unread, "pending mark-read is rebased");
        let local = m.local.unwrap();
        assert!(local.flags.seen);
        assert!(local.literal.is_none(), "bodies are fetched on demand");
        assert!(
            ctx.push.conversation("c1").is_some(),
            "conversation dependency stored"
        );
        assert!(matches!(
            ctx.persisted().action_queue[0].local,
            crate::push::queue::LocalState::Applied(_)
        ));
        assert!(matches!(
            resolve_message(&ctx, "gone").await,
            Err(Error::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn conversation_opening() {
        let stub = test_support::start(Arc::new(responder)).await;
        let ctx = test_support::account(&stub.base).await;
        assert!(matches!(
            open_conversation(&ctx, &Net(false), "c1", "0", false).await,
            Err(Error::Network(_))
        ));
        assert!(
            open_conversation(&ctx, &Net(true), "deleted", "0", false)
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            open_conversation(&ctx, &Net(true), "c1", "6", false).await,
            Err(Error::NotFound(_))
        ));
        let c = open_conversation(&ctx, &Net(true), "c1", "0", false)
            .await
            .unwrap()
            .unwrap();
        let ids: Vec<&str> = c.messages.iter().map(|m| m.metadata.id.as_str()).collect();
        assert_eq!(ids, ["m1", "m2", "m3"]);
        assert_eq!(c.focused_message_id.as_deref(), Some("m2"));

        let c = open_conversation(&ctx, &Net(true), "c1", "0", true)
            .await
            .unwrap()
            .unwrap();
        assert!(c.messages.iter().all(|m| !m.metadata.unread));
        let read = stub
            .seen
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.path == "/mail/v4/messages/read")
            .cloned()
            .unwrap();
        assert_eq!(read.body, serde_json::json!({"IDs": ["m2", "m3"]}));
        let set = ctx.imap_set_for_message("a1").unwrap();
        assert!(set.read().unwrap().message("m3").unwrap().flags.seen);
    }

    #[test]
    fn focus_rule() {
        assert!(focused_message(&[]).is_none());
        let all_read = [m("a", false), m("b", false)];
        assert_eq!(focused_message(&all_read).unwrap().id, "b");
        let run = [
            m("a", true),
            m("b", false),
            m("c", true),
            m("d", true),
            m("e", false),
        ];
        assert_eq!(focused_message(&run).unwrap().id, "c");
        let tail = [m("a", false), m("b", true), m("c", true)];
        assert_eq!(focused_message(&tail).unwrap().id, "b");
    }
}
