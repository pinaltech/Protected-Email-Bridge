//! Command-to-API mapping for one authenticated IMAP session (§11.4,
//! §11.9.2, §11.10, §11.11).
//!
//! The backend is transport-agnostic: an IMAP protocol front-end parses
//! commands and calls these methods, then renders the results.

use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;

use tracing::warn;

use super::mailbox::{
    self, FOLDERS, LABELS, MailboxKind, RECOVERY_ID, is_visible, mailbox_flags, normalize_name,
    wire_name,
};
use super::store::{LocalMessage, Mailbox, MessageFlags};
use crate::account::AddressMode;
use crate::api::mail::{DraftTemplate, ImportMetadata, ImportRequest, draft_action};
use crate::api::types::{Address, Label, label_id, label_type, message_flag};
use crate::config::limits;
use crate::error::Error;
use crate::fingerprint::fingerprint_part;
use crate::gateway::{AccountContext, SharedSet};
use crate::import::encrypt_for_import;
use crate::mime::{Part, parse_address_list, parse_address_list_lenient};
use crate::smtp::dedup::DedupKey;
use crate::smtp::parse::{ensure_text_part, parse_message};
use crate::smtp::pipeline::upload_attachment;
use crate::util::{canonical_email, now_unix};

/// IMAP-level outcome of a failed command.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ImapError {
    /// Tagged `NO`.
    #[error("{0}")]
    No(String),
    /// Tagged `NO [TRYCREATE]`.
    #[error("no such mailbox")]
    TryCreate,
    /// Tagged `BAD`.
    #[error("{0}")]
    Bad(String),
}

impl From<Error> for ImapError {
    fn from(e: Error) -> Self {
        ImapError::No(e.to_string())
    }
}

pub type ImapResult<T> = std::result::Result<T, ImapError>;

/// One `LIST` entry.
#[derive(Debug, Clone)]
pub struct ListEntry {
    pub name: String,
    pub attributes: Vec<&'static str>,
    pub delimiter: char,
    pub subscribed: bool,
}

/// `STATUS` / `SELECT` data.
#[derive(Debug, Clone)]
pub struct MailboxStatus {
    pub id: String,
    pub messages: u32,
    pub recent: u32,
    pub unseen: u32,
    pub uid_next: u32,
    pub uid_validity: u32,
    pub flags: Vec<&'static str>,
    pub permanent_flags: Vec<&'static str>,
    pub first_unseen_seq: Option<u32>,
}

/// `[COPYUID ...]` data.
#[derive(Debug, Clone, Default)]
pub struct CopyResult {
    pub uid_validity: u32,
    pub src_uids: Vec<u32>,
    pub dst_uids: Vec<u32>,
}

/// `[APPENDUID ...]` data.
#[derive(Debug, Clone)]
pub struct AppendResult {
    pub uid_validity: u32,
    pub uid: u32,
}

/// STORE operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagOp {
    Add,
    Remove,
    Replace,
}

/// Backend for one authenticated session.
#[derive(Clone)]
pub struct ImapBackend {
    pub ctx: Arc<AccountContext>,
    pub set: SharedSet,
    /// The address the client logged in with.
    pub address: Address,
}

fn is_forwarded_flag(f: &str) -> bool {
    f.eq_ignore_ascii_case("$Forwarded") || f.eq_ignore_ascii_case("Forwarded")
}

impl ImapBackend {
    pub fn new(ctx: Arc<AccountContext>, set: SharedSet, address: Address) -> Self {
        Self { ctx, set, address }
    }

    fn read<R>(&self, f: impl FnOnce(&super::store::ImapSet) -> R) -> R {
        f(&self.set.read().expect("imap set lock"))
    }

    fn write<R>(&self, f: impl FnOnce(&mut super::store::ImapSet) -> R) -> R {
        f(&mut self.set.write().expect("imap set lock"))
    }

    // ---- mailbox lookup ----------------------------------------------------

    /// Resolve a wire mailbox name.
    pub fn resolve(&self, wire: &str) -> ImapResult<Mailbox> {
        let name = normalize_name(wire).map_err(|e| ImapError::Bad(e.to_string()))?;
        self.read(|s| s.mailbox_by_name(&name).cloned())
            .ok_or_else(|| ImapError::No("no such mailbox".into()))
    }

    fn label_kind(&self, mailbox_id: &str) -> Option<i64> {
        self.ctx.label(mailbox_id).map(|l| l.kind)
    }

    /// `LIST` entries, applying visibility rules (§11.5.3).
    pub fn list(&self) -> Vec<ListEntry> {
        let show = self.ctx.settings.show_all_mail;
        self.read(|s| {
            let mut v: Vec<ListEntry> = s
                .mailboxes()
                .filter(|m| is_visible(&m.id, show, m.len()))
                .map(|m| ListEntry {
                    name: wire_name(&m.name),
                    attributes: mailbox::attributes(&m.kind, &m.id),
                    delimiter: mailbox::DELIMITER,
                    subscribed: m.subscribed,
                })
                .collect();
            v.sort_by(|a, b| a.name.cmp(&b.name));
            v
        })
    }

    /// `SUBSCRIBE` / `UNSUBSCRIBE` (local only, §11.5.5).
    pub fn set_subscribed(&self, wire: &str, on: bool) -> ImapResult<()> {
        let mb = self.resolve(wire)?;
        self.write(|s| {
            if let Some(m) = s.mailbox_mut(&mb.id) {
                m.subscribed = on;
            }
        });
        Ok(())
    }

    /// `STATUS` / `SELECT` data.
    pub fn status(&self, wire: &str) -> ImapResult<MailboxStatus> {
        let mb = self.resolve(wire)?;
        if !mb.is_selectable() {
            return Err(ImapError::No("mailbox is not selectable".into()));
        }
        Ok(self.read(|s| {
            let msgs = s.messages_in(&mb.id);
            let unseen: Vec<u32> = msgs
                .iter()
                .enumerate()
                .filter(|(_, (_, m))| !m.flags.seen)
                .map(|(i, _)| i as u32 + 1)
                .collect();
            let flags = mailbox_flags(&mb.kind, &mb.id).to_vec();
            MailboxStatus {
                id: mb.id.clone(),
                messages: msgs.len() as u32,
                recent: mb.recent.len() as u32,
                unseen: unseen.len() as u32,
                uid_next: mb.uid_next,
                uid_validity: mb.uid_validity,
                permanent_flags: flags.clone(),
                flags,
                first_unseen_seq: unseen.first().copied(),
            }
        }))
    }

    fn msg_ids(&self, mailbox: &str, uids: &[u32]) -> Vec<(u32, String)> {
        self.read(|s| {
            s.mailbox(mailbox)
                .map(|m| {
                    uids.iter()
                        .filter_map(|u| m.uids.get(u).map(|id| (*u, id.clone())))
                        .collect()
                })
                .unwrap_or_default()
        })
    }

    // ---- FETCH ---------------------------------------------------------------

    /// The literal for a message, rebuilding it if missing (§11.10.8).
    pub async fn fetch_literal(&self, mailbox: &str, uid: u32) -> ImapResult<Arc<Vec<u8>>> {
        let Some((_, id)) = self.msg_ids(mailbox, &[uid]).into_iter().next() else {
            return Err(ImapError::No("no such message".into()));
        };
        if let Some(l) = self.read(|s| s.message(&id).and_then(|m| m.literal.clone())) {
            return Ok(l);
        }
        let Some((_, literal, failed)) = self.ctx.fetch_and_build(&id).await? else {
            return Err(ImapError::No("message no longer exists".into()));
        };
        let l = Arc::new(literal);
        self.write(|s| {
            if let Some(m) = s.message_mut(&id) {
                m.literal = Some(l.clone());
                m.failed = failed;
            }
        });
        Ok(l)
    }

    /// Flags of a message in a mailbox, as sent to clients.
    pub fn flags_of(&self, mailbox: &str, uid: u32) -> Vec<String> {
        self.read(|s| {
            let Some(mb) = s.mailbox(mailbox) else {
                return Vec::new();
            };
            mb.uids
                .get(&uid)
                .and_then(|id| s.message(id))
                .map(|m| {
                    m.flags
                        .to_imap(mb.deleted.contains(&uid), mb.recent.contains(&uid))
                })
                .unwrap_or_default()
        })
    }

    // ---- STORE (§11.9.2) -----------------------------------------------------

    pub async fn store(
        &self,
        mailbox: &str,
        uids: &[u32],
        op: FlagOp,
        flags: &[String],
    ) -> ImapResult<()> {
        if op != FlagOp::Remove && flags.iter().any(|f| f.eq_ignore_ascii_case("\\Recent")) {
            return Err(ImapError::Bad("\\Recent is read-only".into()));
        }
        let is_recovery = mailbox == RECOVERY_ID;
        let has = |name: &str| flags.iter().any(|f| f.eq_ignore_ascii_case(name));
        let want_fwd = flags.iter().any(|f| is_forwarded_flag(f));

        let targets = self.msg_ids(mailbox, uids);
        let mut read = Vec::new();
        let mut unread = Vec::new();
        let mut star = Vec::new();
        let mut unstar = Vec::new();
        let mut fwd = Vec::new();
        let mut unfwd = Vec::new();
        let mut new_flags: Vec<(u32, String, MessageFlags, Option<bool>)> = Vec::new();

        for (uid, id) in &targets {
            let Some((cur, deleted)) = self.read(|s| {
                s.message(id).map(|m| {
                    (
                        m.flags.clone(),
                        s.mailbox(mailbox)
                            .is_some_and(|mb| mb.deleted.contains(uid)),
                    )
                })
            }) else {
                continue;
            };
            let set_to = |present: bool, cur: bool| -> bool {
                match op {
                    FlagOp::Add => cur || present,
                    FlagOp::Remove => cur && !present,
                    FlagOp::Replace => present,
                }
            };
            let mut nf = cur.clone();
            nf.seen = set_to(has("\\Seen"), cur.seen);
            nf.flagged = set_to(has("\\Flagged"), cur.flagged);
            nf.answered = set_to(has("\\Answered"), cur.answered);
            nf.draft = set_to(has("\\Draft"), cur.draft);
            nf.forwarded = set_to(want_fwd, cur.forwarded);
            let kws: BTreeSet<String> = flags
                .iter()
                .filter(|f| !f.starts_with('\\') && !is_forwarded_flag(f))
                .cloned()
                .collect();
            match op {
                FlagOp::Add => nf.keywords.extend(kws),
                FlagOp::Remove => nf.keywords.retain(|k| !kws.contains(k)),
                FlagOp::Replace => nf.keywords = kws,
            }
            let new_deleted = set_to(has("\\Deleted"), deleted);

            let local = is_recovery || id.starts_with("local:");
            if !local {
                if nf.seen != cur.seen {
                    if nf.seen {
                        read.push(id.clone())
                    } else {
                        unread.push(id.clone())
                    }
                }
                if nf.flagged != cur.flagged {
                    if nf.flagged {
                        star.push(id.clone())
                    } else {
                        unstar.push(id.clone())
                    }
                }
                if nf.forwarded != cur.forwarded {
                    if nf.forwarded {
                        fwd.push(id.clone())
                    } else {
                        unfwd.push(id.clone())
                    }
                }
            }
            new_flags.push((
                *uid,
                id.clone(),
                nf,
                (new_deleted != deleted).then_some(new_deleted),
            ));
        }

        let c = &self.ctx.client;
        if !read.is_empty() {
            c.mark_read(&read).await?;
        }
        if !unread.is_empty() {
            c.mark_unread(&unread).await?;
        }
        if !star.is_empty() {
            c.label_messages(label_id::STARRED, &star).await?;
        }
        if !unstar.is_empty() {
            c.unlabel_messages(label_id::STARRED, &unstar).await?;
        }
        if !fwd.is_empty() {
            c.mark_forwarded(&fwd).await?;
        }
        if !unfwd.is_empty() {
            c.mark_unforwarded(&unfwd).await?;
        }

        self.write(|s| -> ImapResult<()> {
            for (uid, id, nf, del) in new_flags {
                let star_changed = s
                    .message(&id)
                    .is_some_and(|m| m.flags.flagged != nf.flagged);
                let flagged = nf.flagged;
                s.set_flags(&id, nf);
                if let Some(d) = del {
                    s.set_deleted(mailbox, uid, d);
                }
                if star_changed
                    && !id.starts_with("local:")
                    && s.mailbox(label_id::STARRED).is_some()
                {
                    if let Some(m) = s.message_mut(&id) {
                        m.label_ids.retain(|l| l != label_id::STARRED);
                        if flagged {
                            m.label_ids.push(label_id::STARRED.into());
                        }
                    }
                    if flagged {
                        s.add_to_mailbox(&id, label_id::STARRED)?;
                    } else {
                        s.remove_from_mailbox(&id, label_id::STARRED);
                    }
                }
            }
            Ok(())
        })
    }

    // ---- COPY / MOVE (§11.10.1, §11.10.2) ------------------------------------

    fn check_target(&self, dst: &Mailbox) -> ImapResult<()> {
        if dst.id == label_id::ALL_MAIL
            || dst.id == label_id::ALL_SCHEDULED
            || dst.kind == MailboxKind::Recovery
            || !dst.is_selectable()
        {
            return Err(ImapError::No(
                "operation not allowed for this mailbox".into(),
            ));
        }
        Ok(())
    }

    pub async fn copy(&self, src: &str, uids: &[u32], dst_wire: &str) -> ImapResult<CopyResult> {
        let dst = self.resolve(dst_wire).map_err(|_| ImapError::TryCreate)?;
        self.check_target(&dst)?;
        let msgs = self.msg_ids(src, uids);
        let mut res = CopyResult {
            uid_validity: dst.uid_validity,
            ..Default::default()
        };
        if src == RECOVERY_ID {
            for (uid, id) in msgs {
                let Some(lit) = self.read(|s| s.message(&id).and_then(|m| m.literal.clone()))
                else {
                    continue;
                };
                let a = self.append_to(&dst, &lit, &[], None).await?;
                res.src_uids.push(uid);
                res.dst_uids.push(a.uid);
            }
            return Ok(res);
        }
        let ids: Vec<String> = msgs.iter().map(|(_, id)| id.clone()).collect();
        self.ctx.client.label_messages(&dst.id, &ids).await?;
        self.write(|s| -> ImapResult<()> {
            for (uid, id) in &msgs {
                if let Some(m) = s.message_mut(id)
                    && !m.label_ids.contains(&dst.id)
                {
                    m.label_ids.push(dst.id.clone());
                }
                let new = s.add_to_mailbox(id, &dst.id)?;
                res.src_uids.push(*uid);
                res.dst_uids.push(new);
            }
            Ok(())
        })?;
        Ok(res)
    }

    /// MOVE: returns the COPYUID data and the expunged source UIDs.
    pub async fn move_messages(
        &self,
        src: &str,
        uids: &[u32],
        dst_wire: &str,
    ) -> ImapResult<(CopyResult, Vec<u32>)> {
        let dst = self.resolve(dst_wire).map_err(|_| ImapError::TryCreate)?;
        let forbidden = (src == label_id::INBOX && dst.id == label_id::SENT)
            || (src == label_id::SENT && dst.id == label_id::INBOX)
            || [label_id::ALL_MAIL, label_id::ALL_SCHEDULED].contains(&src);
        if forbidden {
            return Err(ImapError::No("move not allowed".into()));
        }
        self.check_target(&dst)?;
        if src == RECOVERY_ID {
            let res = self.copy(src, uids, dst_wire).await?;
            let msgs = self.msg_ids(src, &res.src_uids);
            let expunged = self.write(|s| {
                msgs.iter()
                    .filter_map(|(_, id)| s.remove_from_mailbox(id, RECOVERY_ID))
                    .collect()
            });
            return Ok((res, expunged));
        }
        let res = self.copy(src, uids, dst_wire).await?;
        let src_kind = self.label_kind(src);
        let dst_kind = self.label_kind(&dst.id);
        let expunge_source = src_kind == Some(label_type::LABEL)
            || matches!(
                dst_kind,
                Some(label_type::FOLDER) | Some(label_type::SYSTEM)
            );
        let mut expunged = Vec::new();
        if expunge_source {
            let msgs = self.msg_ids(src, &res.src_uids);
            let ids: Vec<String> = msgs.iter().map(|(_, id)| id.clone()).collect();
            self.ctx.client.unlabel_messages(src, &ids).await?;
            expunged = self.write(|s| {
                msgs.iter()
                    .filter_map(|(_, id)| {
                        if let Some(m) = s.message_mut(id) {
                            m.label_ids.retain(|l| l != src);
                        }
                        s.remove_from_mailbox(id, src)
                    })
                    .collect()
            });
        }
        Ok((res, expunged))
    }

    // ---- EXPUNGE (§11.10.3) -----------------------------------------------------

    pub async fn expunge(&self, mailbox: &str, only: Option<&[u32]>) -> ImapResult<Vec<u32>> {
        if mailbox == label_id::ALL_MAIL || mailbox == label_id::ALL_SCHEDULED {
            return Err(ImapError::No("expunge not allowed for this mailbox".into()));
        }
        let deleted: Vec<u32> = self.read(|s| {
            s.mailbox(mailbox)
                .map(|m| {
                    let mut v: Vec<u32> = m
                        .deleted
                        .iter()
                        .copied()
                        .filter(|u| only.is_none_or(|o| o.contains(u)))
                        .collect();
                    v.sort_unstable();
                    v
                })
                .unwrap_or_default()
        });
        let msgs = self.msg_ids(mailbox, &deleted);
        if msgs.is_empty() {
            return Ok(Vec::new());
        }
        if mailbox != RECOVERY_ID {
            let ids: Vec<String> = msgs.iter().map(|(_, id)| id.clone()).collect();
            self.ctx.client.unlabel_messages(mailbox, &ids).await?;
            if mailbox == label_id::TRASH || mailbox == label_id::DRAFTS {
                self.permanently_delete_orphans(mailbox, &ids).await?;
            }
        }
        let expunged = self.write(|s| {
            msgs.iter()
                .filter_map(|(_, id)| {
                    if let Some(m) = s.message_mut(id) {
                        m.label_ids.retain(|l| l != mailbox);
                    }
                    s.remove_from_mailbox(id, mailbox)
                })
                .collect()
        });
        Ok(expunged)
    }

    async fn permanently_delete_orphans(&self, mailbox: &str, ids: &[String]) -> ImapResult<()> {
        let metas = self.ctx.client.list_messages_by_id(ids, None).await?;
        let excluded = [
            label_id::ALL_DRAFTS,
            label_id::ALL_SENT,
            label_id::ALL_MAIL,
            label_id::ALL_SCHEDULED,
        ];
        let mut refreshed = false;
        let mut to_delete = Vec::new();
        for m in metas {
            let mut remaining = 0;
            for l in &m.label_ids {
                if excluded.contains(&l.as_str()) || l == mailbox {
                    continue;
                }
                let mut label = self.ctx.label(l);
                if label.is_none() && !refreshed {
                    refreshed = true;
                    if let Ok(found) = self
                        .ctx
                        .client
                        .get_labels_of(&[label_type::FOLDER, label_type::SYSTEM])
                        .await
                    {
                        for f in found {
                            self.ctx.put_label(f);
                        }
                    }
                    label = self.ctx.label(l);
                }
                if label.is_some_and(|x| x.is_wanted()) {
                    remaining += 1;
                }
            }
            if remaining == 0 {
                to_delete.push(m.id);
            }
        }
        if !to_delete.is_empty() {
            self.ctx.client.delete_messages(&to_delete).await?;
        }
        Ok(())
    }

    // ---- APPEND (§11.10.4) --------------------------------------------------------

    pub async fn append(
        &self,
        wire: &str,
        literal: &[u8],
        flags: &[String],
        date: Option<i64>,
    ) -> ImapResult<AppendResult> {
        let name = normalize_name(wire).map_err(|e| ImapError::Bad(e.to_string()))?;
        let mb = self
            .read(|s| s.mailbox_by_name(&name).cloned())
            .ok_or(ImapError::TryCreate)?;
        if mb.id == label_id::ALL_MAIL || mb.kind == MailboxKind::Recovery || !mb.is_selectable() {
            return Err(ImapError::No("APPEND not allowed for this mailbox".into()));
        }
        self.append_to(&mb, literal, flags, date).await
    }

    async fn append_to(
        &self,
        mb: &Mailbox,
        literal: &[u8],
        flags: &[String],
        date: Option<i64>,
    ) -> ImapResult<AppendResult> {
        let has = |n: &str| flags.iter().any(|f| f.eq_ignore_ascii_case(n));
        let is_drafts = mb.id == label_id::DRAFTS;
        let art = self.ctx.art.clone();

        let mut root =
            Part::parse(literal).ok_or_else(|| ImapError::Bad("invalid message".into()))?;
        if !is_drafts {
            validate_headers(&root)?;
        }

        // Step 3: re-APPEND detection.
        if is_drafts {
            root.header.remove(&art.hdr_local_id);
        } else if let Some(local_id) = root.header.get(&art.hdr_local_id) {
            let found = self.read(|s| {
                s.find_by_local_id(local_id.trim()).and_then(|m| {
                    let deleted = s.mailboxes_of(&m.id).iter().any(|mbid| {
                        s.mailbox(mbid)
                            .and_then(|x| x.uid_of(&m.id).map(|u| x.deleted.contains(&u)))
                            .unwrap_or(false)
                    });
                    (!deleted).then(|| m.id.clone())
                })
            });
            if let Some(id) = found {
                if !id.starts_with("local:") {
                    self.ctx
                        .client
                        .label_messages(&mb.id, std::slice::from_ref(&id))
                        .await?;
                }
                let uid = self.write(|s| s.add_to_mailbox(&id, &mb.id))?;
                return Ok(AppendResult {
                    uid_validity: mb.uid_validity,
                    uid,
                });
            }
        }
        let literal: Vec<u8> = if is_drafts {
            root.to_bytes()
        } else {
            literal.to_vec()
        };

        // Step 4: send deduplication.
        let rcpts: Vec<String> = ["To", "Cc", "Bcc"]
            .iter()
            .flat_map(|h| parse_address_list_lenient(&root.header.get_all(h).join(", ")))
            .map(|a| a.address)
            .collect();
        let key = DedupKey::new(fingerprint_part(&root), rcpts);
        if let Some(sent_id) = self.ctx.dedup.query(&key).await {
            return self.bind_service_message(&sent_id, mb).await;
        }

        // Step 5: import target address.
        let target = self.import_address(&root, is_drafts);

        let result = if is_drafts {
            self.append_draft(&literal, &target).await
        } else {
            self.import_literal(
                &mut root,
                &target,
                mb,
                has("\\Flagged"),
                has("\\Seen"),
                has("\\Answered"),
            )
            .await
        };
        match result {
            Ok(id) => self.bind_service_message(&id, mb).await,
            Err(Error::Limit(msg)) => Err(ImapError::No(msg)),
            Err(e) => {
                let dup = self.store_recovered(&literal, flags, date);
                let text = if dup {
                    format!("failed to append message (likely a duplicate): {e}")
                } else {
                    format!("failed to append message: {e}")
                };
                Err(ImapError::No(text))
            }
        }
    }

    /// Fetch a Service message, build its literal and bind it to `mb`.
    async fn bind_service_message(&self, id: &str, mb: &Mailbox) -> ImapResult<AppendResult> {
        let Some((msg, literal, failed)) = self.ctx.fetch_and_build(id).await? else {
            return Err(ImapError::No("appended message no longer exists".into()));
        };
        let lm = self.ctx.local_message(&msg, literal, failed);
        let mut wanted = self.ctx.wanted_mailboxes(&msg.metadata.label_ids);
        if !wanted.contains(&mb.id) {
            wanted.push(mb.id.clone());
        }
        let uid = self.write(|s| -> ImapResult<u32> {
            s.upsert_message(lm, &wanted)?;
            Ok(s.add_to_mailbox(id, &mb.id)?)
        })?;
        Ok(AppendResult {
            uid_validity: mb.uid_validity,
            uid,
        })
    }

    /// Import target address (§11.10.4 step 5).
    fn import_address(&self, root: &Part, is_drafts: bool) -> Address {
        let primary = self
            .ctx
            .primary_address()
            .unwrap_or_else(|| self.address.clone());
        let bound_id = self.read(|s| s.bound_address_id.clone());
        let mut bound = self
            .ctx
            .address(&bound_id)
            .unwrap_or_else(|| self.address.clone());
        if bound.is_external_non_sending() {
            bound = primary;
        }
        if self.ctx.mode() != AddressMode::Combined {
            return bound;
        }
        let from = root
            .header
            .get("From")
            .filter(|v| !v.trim().is_empty())
            .or_else(|| root.header.get("Sender"));
        let candidate = from
            .and_then(|v| parse_address_list_lenient(&v).into_iter().next())
            .and_then(|a| self.ctx.owned_address(&a.address));
        match candidate {
            Some(c) if c.id != bound.id => {
                let unusable =
                    c.is_external_non_sending() || (is_drafts && (!c.is_enabled() || !c.send));
                if unusable { bound } else { c }
            }
            _ => bound,
        }
    }

    async fn append_draft(&self, literal: &[u8], addr: &Address) -> crate::Result<String> {
        let m = parse_message(literal, true)?;
        let ring = self.ctx.keyring(&addr.id)?;
        let body = if !m.rich_body.is_empty() {
            &m.rich_body
        } else {
            &m.plain_body
        };
        let template = DraftTemplate {
            subject: m.subject.clone(),
            sender: crate::api::types::Addr::new(addr.display_name.clone(), addr.email.clone()),
            to_list: m.to.clone(),
            cc_list: m.cc.clone(),
            bcc_list: m.bcc.clone(),
            body: ring.encrypt_armored(body.as_bytes(), false)?,
            mime_type: m.mime_type.clone(),
            unread: false,
            external_id: m.external_id.clone(),
        };
        let draft = self
            .ctx
            .client
            .create_draft(&template, None, draft_action::REPLY)
            .await?;
        for a in &m.attachments {
            let mut a2 = a.clone();
            a2.disposition = if a.disposition == "inline" && a.content_id.is_some() {
                "inline".into()
            } else {
                "attachment".into()
            };
            upload_attachment(&self.ctx, &draft.metadata.id, &a2, &ring).await?;
        }
        Ok(draft.metadata.id)
    }

    async fn import_literal(
        &self,
        root: &mut Part,
        addr: &Address,
        mb: &Mailbox,
        flagged: bool,
        seen: bool,
        answered: bool,
    ) -> crate::Result<String> {
        let ring = self.ctx.keyring(&addr.id)?;
        let mut label_ids = vec![mb.id.clone()];
        if flagged {
            label_ids.push(label_id::STARRED.into());
        }
        let mut flags = if mb.id == label_id::INBOX {
            message_flag::RECEIVED
        } else if mb.id == label_id::SENT {
            message_flag::SENT
        } else if root.header.contains("Received") {
            message_flag::RECEIVED
        } else {
            message_flag::SENT
        };
        if answered {
            flags |= message_flag::REPLIED;
        }
        ensure_text_part(root);
        let plain = root.to_bytes();
        let enc = tokio::task::spawn_blocking(move || encrypt_for_import(&plain, &ring))
            .await
            .map_err(|e| Error::Other(e.to_string()))??;
        if enc.len() as u64 > limits::IMPORT_MESSAGE_CAP {
            return Err(Error::Limit("message exceeds the import size limit".into()));
        }
        let req = ImportRequest {
            literal: enc,
            metadata: ImportMetadata {
                address_id: addr.id.clone(),
                label_ids,
                unread: !seen,
                flags,
            },
        };
        let mut res = self
            .ctx
            .client
            .import_messages(std::slice::from_ref(&req))
            .await?;
        res.pop()
            .unwrap_or_else(|| Err(Error::Other("no import result".into())))
    }

    /// Store a rejected literal in the recovery mailbox (§11.11). Returns
    /// true if an identical literal was already there.
    fn store_recovered(&self, literal: &[u8], flags: &[String], date: Option<i64>) -> bool {
        self.write(|s| {
            let dup = s.messages_in(RECOVERY_ID).iter().any(|(_, m)| {
                m.literal
                    .as_deref()
                    .is_some_and(|l| l.as_slice() == literal)
            });
            if dup {
                return true;
            }
            let mut lm = LocalMessage::new(format!("local:{}", uuid::Uuid::new_v4()));
            lm.literal = Some(Arc::new(literal.to_vec()));
            lm.internal_date = date.unwrap_or_else(now_unix);
            lm.flags.seen = flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen"));
            lm.flags.flagged = flags.iter().any(|f| f.eq_ignore_ascii_case("\\Flagged"));
            let id = lm.id.clone();
            s.insert_message(lm);
            if let Err(e) = s.add_to_mailbox(&id, RECOVERY_ID) {
                warn!("could not store recovered message: {e}");
            }
            false
        })
    }

    // ---- CREATE / RENAME / DELETE (§11.10.5–§11.10.7) ------------------------------

    fn parse_user_mailbox(&self, wire: &str) -> ImapResult<(i64, Vec<String>)> {
        let name = normalize_name(wire).map_err(|e| ImapError::Bad(e.to_string()))?;
        if name.len() < 2 {
            return Err(ImapError::No("operation not allowed".into()));
        }
        match name[0].as_str() {
            LABELS if name.len() == 2 => Ok((label_type::LABEL, name[1..].to_vec())),
            LABELS => Err(ImapError::No("labels cannot be nested".into())),
            FOLDERS => Ok((label_type::FOLDER, name[1..].to_vec())),
            _ => Err(ImapError::No("operation not allowed".into())),
        }
    }

    fn folder_by_path(&self, path: &[String]) -> Option<Label> {
        let labels = self.ctx.labels();
        labels
            .values()
            .find(|l| l.kind == label_type::FOLDER && mailbox::folder_path(l, &labels) == path)
            .cloned()
    }

    pub async fn create(&self, wire: &str) -> ImapResult<()> {
        let (kind, path) = self.parse_user_mailbox(wire)?;
        let leaf = path.last().cloned().unwrap_or_default();
        let parent = if kind == label_type::FOLDER && path.len() > 1 {
            Some(
                self.folder_by_path(&path[..path.len() - 1])
                    .ok_or_else(|| ImapError::No("parent folder does not exist".into()))?
                    .id,
            )
        } else {
            None
        };
        let label = self
            .ctx
            .client
            .create_label(&leaf, limits::NEW_LABEL_COLOR, kind, parent.as_deref())
            .await?;
        self.ctx.put_label(label.clone());
        self.ctx.apply_label(&label)?;
        Ok(())
    }

    pub async fn rename(&self, old_wire: &str, new_wire: &str) -> ImapResult<()> {
        let mb = self.resolve(old_wire)?;
        let current = self
            .ctx
            .label(&mb.id)
            .ok_or_else(|| ImapError::No("mailbox cannot be renamed".into()))?;
        let (kind, path) = self.parse_user_mailbox(new_wire)?;
        if kind != current.kind {
            return Err(ImapError::No(
                "cannot move between Folders and Labels".into(),
            ));
        }
        let leaf = path.last().cloned().unwrap_or_default();
        let label = if kind == label_type::LABEL {
            let fresh = self
                .ctx
                .client
                .get_label(&mb.id, &[label_type::LABEL])
                .await?;
            self.ctx
                .client
                .update_label(&mb.id, &leaf, &fresh.color, None)
                .await?
        } else {
            let parent = if path.len() > 1 {
                Some(
                    self.folder_by_path(&path[..path.len() - 1])
                        .ok_or_else(|| ImapError::No("parent folder does not exist".into()))?
                        .id,
                )
            } else {
                None
            };
            self.ctx
                .client
                .update_label(&mb.id, &leaf, &current.color, parent.as_deref())
                .await?
        };
        self.ctx.put_label(label.clone());
        self.ctx.apply_label(&label)?;
        Ok(())
    }

    pub async fn delete(&self, wire: &str) -> ImapResult<()> {
        let mb = self.resolve(wire)?;
        if self
            .ctx
            .label(&mb.id)
            .is_none_or(|l| l.kind == label_type::SYSTEM)
        {
            return Err(ImapError::No("mailbox cannot be deleted".into()));
        }
        self.ctx.client.delete_label(&mb.id).await?;
        self.ctx.remove_label(&mb.id);
        self.ctx.delete_label_mailbox(&mb.id);
        Ok(())
    }

    /// All owned emails (for SEARCH and similar local evaluation).
    pub fn owned_emails(&self) -> HashSet<String> {
        self.ctx
            .addresses()
            .iter()
            .map(|a| canonical_email(&a.email))
            .collect()
    }
}

/// APPEND header validation (§11.10.4 step 2).
pub fn validate_headers(root: &Part) -> ImapResult<()> {
    let h = &root.header;
    let date = h.get("Date").unwrap_or_default();
    if date.trim().is_empty() {
        return Err(ImapError::Bad("missing Date header".into()));
    }
    let from = h.get("From").unwrap_or_default();
    let from_list = parse_address_list(&from)
        .filter(|l| !l.is_empty())
        .ok_or_else(|| ImapError::Bad("missing or invalid From header".into()))?;
    let sender = h.get("Sender");
    if from_list.len() > 1 && sender.as_deref().and_then(parse_address_list).is_none() {
        return Err(ImapError::Bad(
            "Sender required with multiple From mailboxes".into(),
        ));
    }
    if let Some(s) = sender
        && (s.trim().is_empty() || parse_address_list(&s).is_none())
    {
        return Err(ImapError::Bad("invalid Sender header".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_validation() {
        let ok =
            Part::parse(b"Date: Mon, 1 Jan 2024 00:00:00 +0000\r\nFrom: a@b.c\r\n\r\nx").unwrap();
        assert!(validate_headers(&ok).is_ok());
        let no_date = Part::parse(b"From: a@b.c\r\n\r\nx").unwrap();
        assert!(validate_headers(&no_date).is_err());
        let multi = Part::parse(b"Date: x\r\nFrom: a@b.c, d@e.f\r\n\r\nx").unwrap();
        assert!(validate_headers(&multi).is_err());
        let multi_ok =
            Part::parse(b"Date: x\r\nFrom: a@b.c, d@e.f\r\nSender: a@b.c\r\n\r\nx").unwrap();
        assert!(validate_headers(&multi_ok).is_ok());
    }
}
