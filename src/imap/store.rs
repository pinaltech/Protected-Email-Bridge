//! Local IMAP state for one mailbox set (§10.3, §11.6, §11.7, §11.13).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use tokio::sync::broadcast;

use super::mailbox::{
    FOLDERS, FOLDERS_ID, LABELS, LABELS_ID, MailboxKind, RECOVERY_ID, UidValidityGenerator,
};
use crate::api::types::MessageMetadata;
use crate::error::{Error, Result};

/// Service message ID, or a `local:` ID for recovery-mailbox messages.
pub type MessageId = String;

/// IMAP flags of a message (§11.9.1) plus local-only keywords.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MessageFlags {
    pub seen: bool,
    pub flagged: bool,
    pub draft: bool,
    pub answered: bool,
    pub forwarded: bool,
    pub keywords: BTreeSet<String>,
}

impl MessageFlags {
    /// Derive flags from Service metadata (§11.9.1).
    pub fn from_metadata(m: &MessageMetadata) -> Self {
        Self {
            seen: m.is_seen(),
            flagged: m.is_starred(),
            draft: m.is_draft(),
            answered: m.is_replied || m.is_replied_all,
            forwarded: m.is_forwarded,
            keywords: BTreeSet::new(),
        }
    }

    /// Keep local-only state (keywords, \Answered set locally) from `old`.
    pub fn merge_local(mut self, old: &MessageFlags) -> Self {
        self.keywords = old.keywords.clone();
        self.answered |= old.answered;
        self
    }

    /// The flag list as sent to clients.
    pub fn to_imap(&self, deleted: bool, recent: bool) -> Vec<String> {
        let mut v = Vec::new();
        if self.seen {
            v.push("\\Seen".into());
        }
        if self.flagged {
            v.push("\\Flagged".into());
        }
        if self.draft {
            v.push("\\Draft".into());
        }
        if self.answered {
            v.push("\\Answered".into());
        }
        if deleted {
            v.push("\\Deleted".into());
        }
        if recent {
            v.push("\\Recent".into());
        }
        if self.forwarded {
            v.push("$Forwarded".into());
            v.push("Forwarded".into());
        }
        v.extend(self.keywords.iter().cloned());
        v
    }
}

/// A message as held by the IMAP server.
#[derive(Debug, Clone)]
pub struct LocalMessage {
    pub id: MessageId,
    /// Local identity carried in `HDR_LOCAL_ID` (§11.10.4 step 3).
    pub local_id: String,
    /// The built literal, served byte-identically on every FETCH.
    pub literal: Option<Arc<Vec<u8>>>,
    pub internal_date: i64,
    pub flags: MessageFlags,
    pub label_ids: Vec<String>,
    pub address_id: String,
    /// The literal is a build-failure placeholder (§11.8.5).
    pub failed: bool,
}

impl LocalMessage {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            local_id: uuid::Uuid::new_v4().to_string(),
            literal: None,
            internal_date: 0,
            flags: MessageFlags::default(),
            label_ids: Vec::new(),
            address_id: String::new(),
            failed: false,
        }
    }

    /// Size of the built literal (`RFC822.SIZE`).
    pub fn size(&self) -> usize {
        self.literal.as_ref().map(|l| l.len()).unwrap_or(0)
    }

    pub fn is_local(&self) -> bool {
        self.id.starts_with("local:")
    }
}

/// One mailbox.
#[derive(Debug, Clone)]
pub struct Mailbox {
    /// Service label ID, or a local ID for placeholders/recovery.
    pub id: String,
    pub name: Vec<String>,
    pub kind: MailboxKind,
    pub uid_validity: u32,
    pub uid_next: u32,
    pub uids: BTreeMap<u32, MessageId>,
    by_msg: HashMap<MessageId, u32>,
    /// `\Deleted` is local and scoped to the mailbox (§11.9.2).
    pub deleted: HashSet<u32>,
    pub recent: HashSet<u32>,
    pub subscribed: bool,
}

impl Mailbox {
    fn new(id: String, name: Vec<String>, kind: MailboxKind, uid_validity: u32) -> Self {
        Self {
            id,
            name,
            kind,
            uid_validity,
            uid_next: 1,
            uids: BTreeMap::new(),
            by_msg: HashMap::new(),
            deleted: HashSet::new(),
            recent: HashSet::new(),
            subscribed: true,
        }
    }

    pub fn uid_of(&self, msg: &str) -> Option<u32> {
        self.by_msg.get(msg).copied()
    }

    pub fn len(&self) -> usize {
        self.uids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.uids.is_empty()
    }

    pub fn is_selectable(&self) -> bool {
        self.kind != MailboxKind::Placeholder
    }

    /// 1-based sequence number of a UID.
    pub fn seq_of(&self, uid: u32) -> Option<u32> {
        self.uids
            .range(..=uid)
            .count()
            .try_into()
            .ok()
            .filter(|_| self.uids.contains_key(&uid))
    }
}

/// An unsolicited change notification (§11.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Update {
    Exists { mailbox: String, uid: u32 },
    Expunge { mailbox: String, uid: u32 },
    Flags { mailbox: String, uid: u32 },
    MailboxDeleted { mailbox: String },
    MailboxRenamed { mailbox: String },
}

/// The local state of one IMAP mailbox set.
pub struct ImapSet {
    pub bound_address_id: String,
    mailboxes: HashMap<String, Mailbox>,
    messages: HashMap<MessageId, LocalMessage>,
    uidv: Arc<UidValidityGenerator>,
    updates: broadcast::Sender<Update>,
}

impl ImapSet {
    pub fn new(bound_address_id: impl Into<String>, uidv: Arc<UidValidityGenerator>) -> Self {
        let (tx, _) = broadcast::channel(4096);
        Self {
            bound_address_id: bound_address_id.into(),
            mailboxes: HashMap::new(),
            messages: HashMap::new(),
            uidv,
            updates: tx,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Update> {
        self.updates.subscribe()
    }

    fn notify(&self, u: Update) {
        let _ = self.updates.send(u);
    }

    /// Remove all local data (mode change, refresh, §10.3, §12.3.1).
    pub fn clear(&mut self) {
        for id in self.mailboxes.keys().cloned().collect::<Vec<_>>() {
            self.notify(Update::MailboxDeleted { mailbox: id });
        }
        self.mailboxes.clear();
        self.messages.clear();
    }

    // ---- mailboxes -------------------------------------------------------

    pub fn mailboxes(&self) -> impl Iterator<Item = &Mailbox> {
        self.mailboxes.values()
    }

    pub fn mailbox(&self, id: &str) -> Option<&Mailbox> {
        self.mailboxes.get(id)
    }

    pub fn mailbox_mut(&mut self, id: &str) -> Option<&mut Mailbox> {
        self.mailboxes.get_mut(id)
    }

    /// Find a mailbox by name components (case-sensitive except INBOX).
    pub fn mailbox_by_name(&self, name: &[String]) -> Option<&Mailbox> {
        self.mailboxes.values().find(|m| names_equal(&m.name, name))
    }

    /// Create a mailbox. Fails if the name is held by a different ID; the
    /// caller resolves such conflicts (§11.14).
    pub fn create_mailbox(&mut self, id: &str, name: Vec<String>, kind: MailboxKind) -> Result<()> {
        if let Some(existing) = self.mailbox_by_name(&name)
            && existing.id != id
        {
            return Err(Error::Invalid(format!(
                "mailbox name {} is held by {}",
                name.join("/"),
                existing.id
            )));
        }
        if let Some(m) = self.mailboxes.get_mut(id) {
            m.name = name;
            m.kind = kind;
            return Ok(());
        }
        if self.mailboxes.len() >= u32::MAX as usize {
            return Err(Error::Limit("too many mailboxes".into()));
        }
        let uv = self.uidv.next()?;
        self.mailboxes
            .insert(id.to_string(), Mailbox::new(id.to_string(), name, kind, uv));
        Ok(())
    }

    pub fn rename_mailbox(&mut self, id: &str, name: Vec<String>) -> Result<()> {
        if let Some(existing) = self.mailbox_by_name(&name)
            && existing.id != id
        {
            return Err(Error::Invalid("target name in use".into()));
        }
        let m = self
            .mailboxes
            .get_mut(id)
            .ok_or_else(|| Error::NotFound(format!("mailbox {id}")))?;
        m.name = name;
        self.notify(Update::MailboxRenamed {
            mailbox: id.to_string(),
        });
        Ok(())
    }

    pub fn delete_mailbox(&mut self, id: &str) -> Option<Mailbox> {
        let m = self.mailboxes.remove(id)?;
        self.notify(Update::MailboxDeleted {
            mailbox: id.to_string(),
        });
        // Drop messages no longer in any mailbox.
        for msg in m.uids.values() {
            if !self
                .mailboxes
                .values()
                .any(|mb| mb.by_msg.contains_key(msg))
            {
                self.messages.remove(msg);
            }
        }
        Some(m)
    }

    /// Ensure the `Folders`/`Labels` placeholders and the recovery mailbox
    /// exist (§11.5.1, §11.11, §11.14 step 3).
    pub fn ensure_local_mailboxes(
        &mut self,
        recovery_name: &str,
        service_labels: &HashSet<String>,
    ) -> Result<()> {
        for (id, name) in [(FOLDERS_ID, FOLDERS), (LABELS_ID, LABELS)] {
            let n = vec![name.to_string()];
            if let Some(holder) = self.mailbox_by_name(&n).map(|m| m.id.clone())
                && holder != id
            {
                if service_labels.contains(&holder) {
                    return Err(Error::Invalid(format!(
                        "placeholder name {name} is held by a Service label"
                    )));
                }
                self.delete_mailbox(&holder);
            }
            self.create_mailbox(id, n, MailboxKind::Placeholder)?;
        }
        if self.mailbox(RECOVERY_ID).is_none() {
            self.create_mailbox(
                RECOVERY_ID,
                vec![recovery_name.to_string()],
                MailboxKind::Recovery,
            )?;
        }
        Ok(())
    }

    // ---- messages --------------------------------------------------------

    pub fn message(&self, id: &str) -> Option<&LocalMessage> {
        self.messages.get(id)
    }

    pub fn message_mut(&mut self, id: &str) -> Option<&mut LocalMessage> {
        self.messages.get_mut(id)
    }

    pub fn messages(&self) -> impl Iterator<Item = &LocalMessage> {
        self.messages.values()
    }

    pub fn find_by_local_id(&self, local_id: &str) -> Option<&LocalMessage> {
        self.messages.values().find(|m| m.local_id == local_id)
    }

    /// Messages of a mailbox in UID order.
    pub fn messages_in(&self, mailbox: &str) -> Vec<(u32, &LocalMessage)> {
        let Some(m) = self.mailboxes.get(mailbox) else {
            return Vec::new();
        };
        m.uids
            .iter()
            .filter_map(|(uid, id)| self.messages.get(id).map(|msg| (*uid, msg)))
            .collect()
    }

    /// Add a message to one mailbox, returning its UID there.
    pub fn add_to_mailbox(&mut self, msg: &str, mailbox: &str) -> Result<u32> {
        if !self.messages.contains_key(msg) {
            return Err(Error::NotFound(format!("message {msg}")));
        }
        let m = self
            .mailboxes
            .get_mut(mailbox)
            .ok_or_else(|| Error::NotFound(format!("mailbox {mailbox}")))?;
        if let Some(uid) = m.by_msg.get(msg) {
            return Ok(*uid);
        }
        let uid = m.uid_next;
        m.uid_next = uid
            .checked_add(1)
            .ok_or_else(|| Error::Limit("UID space exhausted".into()))?;
        m.uids.insert(uid, msg.to_string());
        m.by_msg.insert(msg.to_string(), uid);
        m.recent.insert(uid);
        self.notify(Update::Exists {
            mailbox: mailbox.to_string(),
            uid,
        });
        Ok(uid)
    }

    /// Remove a message from one mailbox (expunge), returning its old UID.
    pub fn remove_from_mailbox(&mut self, msg: &str, mailbox: &str) -> Option<u32> {
        let m = self.mailboxes.get_mut(mailbox)?;
        let uid = m.by_msg.remove(msg)?;
        m.uids.remove(&uid);
        m.deleted.remove(&uid);
        m.recent.remove(&uid);
        self.notify(Update::Expunge {
            mailbox: mailbox.to_string(),
            uid,
        });
        if !self
            .mailboxes
            .values()
            .any(|mb| mb.by_msg.contains_key(msg))
        {
            self.messages.remove(msg);
        }
        Some(uid)
    }

    /// Insert or update a message and set its mailbox membership to exactly
    /// `mailboxes` (the recovery mailbox is never touched).
    pub fn upsert_message(&mut self, mut msg: LocalMessage, mailboxes: &[String]) -> Result<()> {
        let id = msg.id.clone();
        let flags_changed = match self.messages.get(&id) {
            Some(old) => {
                msg.local_id = old.local_id.clone();
                if msg.literal.is_none() {
                    msg.literal = old.literal.clone();
                    msg.failed = old.failed;
                }

                old.flags != msg.flags
            }
            None => false,
        };
        self.messages.insert(id.clone(), msg);
        self.set_membership(&id, mailboxes)?;
        if flags_changed {
            self.notify_flags(&id);
        }
        Ok(())
    }

    /// Replace a message (new literal, new UIDs in every mailbox, §12.3.5).
    pub fn replace_message(&mut self, msg: LocalMessage, mailboxes: &[String]) -> Result<()> {
        let id = msg.id.clone();
        let current: Vec<String> = self
            .mailboxes
            .values()
            .filter(|m| m.by_msg.contains_key(&id))
            .map(|m| m.id.clone())
            .collect();
        let old_local = self.messages.get(&id).map(|m| m.local_id.clone());
        for mb in current {
            if let Some(m) = self.mailboxes.get_mut(&mb)
                && let Some(uid) = m.by_msg.remove(&id)
            {
                m.uids.remove(&uid);
                m.deleted.remove(&uid);
                m.recent.remove(&uid);
                self.notify(Update::Expunge { mailbox: mb, uid });
            }
        }
        let mut msg = msg;
        if let Some(l) = old_local {
            msg.local_id = l;
        }
        self.messages.insert(id.clone(), msg);
        self.set_membership(&id, mailboxes)
    }

    /// Set membership to exactly `mailboxes` (existing UIDs are kept).
    pub fn set_membership(&mut self, msg: &str, mailboxes: &[String]) -> Result<()> {
        let current: Vec<String> = self
            .mailboxes
            .values()
            .filter(|m| m.by_msg.contains_key(msg) && m.kind != MailboxKind::Recovery)
            .map(|m| m.id.clone())
            .collect();
        for mb in mailboxes {
            if self.mailboxes.contains_key(mb) && !current.contains(mb) {
                self.add_to_mailbox(msg, mb)?;
            }
        }
        for mb in current {
            if !mailboxes.contains(&mb) {
                self.remove_from_mailbox(msg, &mb);
            }
        }
        Ok(())
    }

    /// Remove a message from every mailbox.
    pub fn remove_message(&mut self, msg: &str) {
        let mbs: Vec<String> = self
            .mailboxes
            .values()
            .filter(|m| m.by_msg.contains_key(msg))
            .map(|m| m.id.clone())
            .collect();
        for mb in mbs {
            self.remove_from_mailbox(msg, &mb);
        }
        self.messages.remove(msg);
    }

    /// Update the flags of a message and notify every mailbox.
    pub fn set_flags(&mut self, msg: &str, flags: MessageFlags) {
        let changed = match self.messages.get_mut(msg) {
            Some(m) if m.flags != flags => {
                m.flags = flags;
                true
            }
            _ => false,
        };
        if changed {
            self.notify_flags(msg);
        }
    }

    /// Set or clear `\Deleted` for a UID in a mailbox.
    pub fn set_deleted(&mut self, mailbox: &str, uid: u32, deleted: bool) {
        if let Some(m) = self.mailboxes.get_mut(mailbox) {
            let changed = if deleted {
                m.deleted.insert(uid)
            } else {
                m.deleted.remove(&uid)
            };
            if changed {
                self.notify(Update::Flags {
                    mailbox: mailbox.to_string(),
                    uid,
                });
            }
        }
    }

    fn notify_flags(&self, msg: &str) {
        for m in self.mailboxes.values() {
            if let Some(uid) = m.by_msg.get(msg) {
                self.notify(Update::Flags {
                    mailbox: m.id.clone(),
                    uid: *uid,
                });
            }
        }
    }

    /// Insert a message without any membership (used before APPEND binds it).
    pub fn insert_message(&mut self, msg: LocalMessage) {
        self.messages.insert(msg.id.clone(), msg);
    }

    /// Mailboxes (IDs) containing a message.
    pub fn mailboxes_of(&self, msg: &str) -> Vec<String> {
        self.mailboxes
            .values()
            .filter(|m| m.by_msg.contains_key(msg))
            .map(|m| m.id.clone())
            .collect()
    }
}

/// Mailbox name equality (INBOX is case-insensitive).
pub fn names_equal(a: &[String], b: &[String]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).enumerate().all(|(i, (x, y))| {
            if i == 0 && x.eq_ignore_ascii_case("INBOX") {
                y.eq_ignore_ascii_case("INBOX")
            } else {
                x == y
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn membership_and_uids() {
        let mut s = ImapSet::new("addr", Arc::new(UidValidityGenerator::new()));
        s.create_mailbox("0", vec!["INBOX".into()], MailboxKind::System)
            .unwrap();
        s.create_mailbox("10", vec!["Starred".into()], MailboxKind::System)
            .unwrap();
        let mut rx = s.subscribe();
        let mut m = LocalMessage::new("m1");
        m.flags.seen = true;
        s.upsert_message(m.clone(), &["0".into(), "10".into()])
            .unwrap();
        assert_eq!(s.mailbox("0").unwrap().uid_of("m1"), Some(1));
        assert_eq!(s.mailbox("10").unwrap().uid_of("m1"), Some(1));
        assert!(matches!(rx.try_recv().unwrap(), Update::Exists { .. }));
        s.set_membership("m1", &["0".into()]).unwrap();
        assert!(s.mailbox("10").unwrap().is_empty());
        s.replace_message(m, &["0".into()]).unwrap();
        assert_eq!(s.mailbox("0").unwrap().uid_of("m1"), Some(2));
        assert_eq!(s.mailbox("0").unwrap().seq_of(2), Some(1));
        s.remove_message("m1");
        assert!(s.message("m1").is_none());
    }

    #[test]
    fn name_conflict_detected() {
        let mut s = ImapSet::new("addr", Arc::new(UidValidityGenerator::new()));
        s.create_mailbox("a", vec!["Labels".into(), "x".into()], MailboxKind::Label)
            .unwrap();
        assert!(
            s.create_mailbox("b", vec!["Labels".into(), "x".into()], MailboxKind::Label)
                .is_err()
        );
    }
}
