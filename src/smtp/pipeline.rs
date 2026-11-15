//! The SMTP submission pipeline (§13.5–§13.11, §13.15).

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use tracing::{info, warn};

use super::dedup::{Begin, DedupKey};
use super::package::build_packages;
use super::parse::{
    OutAttachment, ParsedMessage, attach_public_key, ensure_text_part, finish_model, parse_message,
    trim_end_of_data,
};
use super::prefs;
use crate::account::AddressMode;
use crate::api::mail::{AttachmentUpload, DraftTemplate, MessageFilter, draft_action};
use crate::api::types::{Addr, Address, MessageMetadata};
use crate::crypto::{self, KeyRing, SessionKey};
use crate::error::Error;
use crate::fingerprint::fingerprint_part;
use crate::gateway::AccountContext;
use crate::util::{b64_decode, canonical_email, plus_tag};

/// Submission errors with their client-facing text (§13.15).
#[derive(Debug, Clone, thiserror::Error)]
pub enum SubmitError {
    #[error(
        "No email was sent. The address {0} does not exist. Correct the recipient and resend the message"
    )]
    RecipientDoesNotExist(String),
    #[error(
        "No email was sent. One or more addresses do not exist. Correct the recipients and resend the message"
    )]
    RecipientsDoNotExist,
    #[error("This message couldn't be sent because the email client sent a malformed message")]
    Malformed,
    #[error("message too large")]
    TooLarge,
    #[error("invalid list of recipients")]
    InvalidRecipientList,
    #[error("You cannot send from this address: {0}. Check your email client and gateway settings")]
    CannotSendFromAddress(String),
    #[error("Too many failed send attempts. Try again later")]
    Throttled,
    #[error(
        "The sender address is not valid for this account. Check your email client and account settings, or choose a different sender address"
    )]
    SenderAddressNotOwned,
    #[error("This message uses an unsupported message format. Try plain text or HTML")]
    UnsupportedOutgoingMime,
    #[error(
        "User Authentication failed. Please check the outgoing server configuration in your mail client and try again"
    )]
    AuthFailed,
    #[error(
        "The account is not available in the gateway. Verify the outgoing server settings in your mail client and try again"
    )]
    NoSuchUser,
    #[error(
        "The sender or recipient address is not valid. Review the addresses and resend the message"
    )]
    InvalidRecipient,
    #[error(
        "The sender or recipient address is not valid. Review the addresses and resend the message"
    )]
    InvalidReturnPath,
    #[error("{0}")]
    Other(String),
}

impl SubmitError {
    /// The full SMTP reply line.
    pub fn smtp_reply(&self) -> String {
        format!("554 5.0.0 Error: {self}")
    }
}

impl From<Error> for SubmitError {
    fn from(e: Error) -> Self {
        match &e {
            Error::NotFound(s) if s.starts_with("recipient:") => {
                SubmitError::RecipientDoesNotExist(s.trim_start_matches("recipient:").to_string())
            }
            Error::Deauthenticated => SubmitError::AuthFailed,
            _ => SubmitError::Other(e.to_string()),
        }
    }
}

/// One submission (§13.5).
#[derive(Debug, Clone)]
pub struct Submission {
    pub reverse_path: String,
    pub recipients: Vec<String>,
    pub data: Vec<u8>,
}

/// Run the submission pipeline. Returns the sent Service message ID.
pub async fn submit(
    ctx: Option<&Arc<AccountContext>>,
    auth_address_id: &str,
    sub: Submission,
) -> Result<String, SubmitError> {
    let recipients: Vec<String> = sub
        .recipients
        .iter()
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
        .collect();
    if recipients.is_empty() {
        return Err(SubmitError::InvalidRecipient);
    }
    let ctx = ctx.ok_or(SubmitError::NoSuchUser)?;

    let t = Instant::now();
    if !ctx.smtp_throttle.lock().expect("throttle").check(t) {
        return Err(SubmitError::Throttled);
    }
    let result = submit_inner(
        ctx,
        auth_address_id,
        &sub.reverse_path,
        &recipients,
        &sub.data,
    )
    .await;
    ctx.smtp_throttle
        .lock()
        .expect("throttle")
        .record(t, result.is_err());
    result
}

async fn submit_inner(
    ctx: &Arc<AccountContext>,
    auth_address_id: &str,
    reverse_path: &str,
    recipients: &[String],
    data: &[u8],
) -> Result<String, SubmitError> {
    let mut from = reverse_path.to_string();
    if ctx.owned_address(&from).is_none() {
        return Err(SubmitError::InvalidReturnPath);
    }
    let data = trim_end_of_data(data);

    // Parse before dedup so the fingerprint is computed on the same tree.
    let parsed = parse_message(data, false).map_err(|_| SubmitError::Malformed)?;
    let key = DedupKey::new(fingerprint_part(&parsed.root), recipients.iter().cloned());
    if let Begin::AlreadySent(id) = ctx.dedup.begin(&key).await {
        info!("duplicate submission suppressed");
        return Ok(id);
    }
    match send(ctx, auth_address_id, &mut from, recipients, parsed).await {
        Ok(id) => {
            ctx.dedup.mark_sent(&key, &id);
            Ok(id)
        }
        Err(e) => {
            ctx.dedup.remove(&key);
            Err(e)
        }
    }
}

async fn send(
    ctx: &Arc<AccountContext>,
    auth_address_id: &str,
    from: &mut String,
    recipients: &[String],
    parsed: ParsedMessage,
) -> Result<String, SubmitError> {
    // Step 7.
    if let Some(f) = &parsed.from {
        *from = f.address.clone();
    }
    let sender = ctx
        .owned_address(from)
        .ok_or(SubmitError::InvalidReturnPath)?;
    // Step 8.
    if !(sender.send && sender.is_enabled()) {
        return Err(SubmitError::CannotSendFromAddress(sender.email.clone()));
    }
    // Steps 9–10.
    let settings = ctx.mail_settings().await?;
    let ring = ctx.keyring(&sender.id)?;
    let first = ring.first()?;

    // Steps 11–13.
    let mut root = parsed.root;
    ensure_text_part(&mut root);
    if settings.attach_public_key {
        let pk = first.public_key();
        let armored = crypto::armored_public_key(&pk)?;
        attach_public_key(
            &mut root,
            &armored,
            &crypto::first_identity_name(&pk),
            &crypto::fingerprint_hex(&pk),
        );
    }
    let model = finish_model(root, false).map_err(|_| SubmitError::Malformed)?;

    // Step 14.
    let (parent, drafts_to_delete) = resolve_parent(ctx, &model, auth_address_id).await;

    // Step 15.
    let draft = create_draft(
        ctx,
        &model,
        from,
        &sender,
        recipients,
        &ring,
        parent.as_deref(),
    )
    .await?;
    let draft_id = draft.metadata.id.clone();

    // Step 16.
    let att_keys = upload_attachments(ctx, &draft_id, &model.attachments, &ring).await?;

    // Step 17.
    let mut all: Vec<String> = Vec::new();
    for a in draft
        .metadata
        .to_list
        .iter()
        .chain(&draft.metadata.cc_list)
        .chain(&draft.metadata.bcc_list)
    {
        if !all.iter().any(|x| x.eq_ignore_ascii_case(&a.address)) {
            all.push(a.address.clone());
        }
    }
    let lookups = all
        .iter()
        .map(|email| prefs::resolve(ctx, email, &model.mime_type, &settings));
    let resolved = futures::future::join_all(lookups).await;
    let mut recips = Vec::new();
    for (email, r) in all.iter().zip(resolved) {
        match r {
            Ok(p) => recips.push((email.clone(), p)),
            Err(Error::NotFound(s)) if s.starts_with("recipient:") => {
                return Err(SubmitError::RecipientDoesNotExist(email.clone()));
            }
            Err(e) => return Err(e.into()),
        }
    }

    // Step 18.
    let packages = build_packages(
        &ring,
        &recips,
        &model.rich_body,
        &model.plain_body,
        &model.mime_body,
        &att_keys,
    )?;
    let sent = ctx.client.send_draft(&draft_id, &packages).await?;

    // Step 19.
    if !drafts_to_delete.is_empty()
        && let Err(e) = ctx.client.delete_messages(&drafts_to_delete).await
    {
        warn!("failed to delete replaced drafts: {e}");
    }
    Ok(sent.metadata.id)
}

/// Parent resolution (§13.9). Returns (parent ID, drafts to delete).
pub async fn resolve_parent(
    ctx: &AccountContext,
    m: &ParsedMessage,
    auth_address_id: &str,
) -> (Option<String>, Vec<String>) {
    let domain = format!("@{}", ctx.art.internal_id_domain);
    let mut refs = m.references.clone();
    if let Some(r) = &m.in_reply_to {
        refs.push(r.clone());
    }
    let (internal, external): (Vec<String>, Vec<String>) =
        refs.into_iter().partition(|r| r.contains(&domain));
    let addr_filter = (ctx.mode() == AddressMode::Split).then(|| auth_address_id.to_string());

    let mut parent: Option<String> = None;
    let mut drafts = Vec::new();
    for r in internal {
        let id = r.split(&domain).next().unwrap_or_default().to_string();
        match ctx
            .client
            .list_messages_by_id(std::slice::from_ref(&id), addr_filter.as_deref())
            .await
        {
            Ok(list) => {
                for meta in list {
                    if meta.is_draft() {
                        drafts.push(meta.id);
                    } else {
                        parent = Some(meta.id);
                    }
                }
            }
            Err(e) => warn!("parent lookup failed: {e}"),
        }
    }
    if parent.is_none()
        && let Some(last) = external.last()
    {
        let filter = MessageFilter {
            external_id: last.clone(),
            address_id: addr_filter.unwrap_or_default(),
            ..Default::default()
        };
        match ctx.client.list_messages(&filter, 0, 150).await {
            Ok(list) => parent = pick_external_parent(&list),
            Err(e) => warn!("parent lookup failed: {e}"),
        }
    }
    (parent, drafts)
}

fn pick_external_parent(list: &[MessageMetadata]) -> Option<String> {
    match list {
        [] => None,
        [one] => (one.is_sent() || one.is_received()).then(|| one.id.clone()),
        many => many.iter().find(|m| m.is_sent()).map(|m| m.id.clone()),
    }
}

/// Canonicalise a sender address keeping a `+tag` (§13.7).
pub fn canonical_sender(header_addr: &str, owned: &Address) -> String {
    match (plus_tag(header_addr), owned.email.rsplit_once('@')) {
        (Some(tag), Some((local, domain))) => format!("{local}+{tag}@{domain}"),
        _ => owned.email.clone(),
    }
}

/// Draft creation (§13.10).
async fn create_draft(
    ctx: &AccountContext,
    m: &ParsedMessage,
    reverse_path: &str,
    _sender_addr: &Address,
    recipients: &[String],
    ring: &KeyRing,
    parent: Option<&str>,
) -> Result<crate::api::types::Message, SubmitError> {
    let mut sender = m
        .from
        .clone()
        .unwrap_or_else(|| Addr::new("", reverse_path));
    if sender.address.is_empty() {
        sender.address = reverse_path.to_string();
    }
    let owned = ctx
        .owned_address(&sender.address)
        .ok_or(SubmitError::SenderAddressNotOwned)?;
    sender.address = canonical_sender(&sender.address, &owned);

    let in_r = |a: &Addr| {
        recipients
            .iter()
            .any(|r| r.eq_ignore_ascii_case(&a.address))
    };
    let to: Vec<Addr> = m.to.iter().filter(|a| in_r(a)).cloned().collect();
    let cc = m.cc.clone();
    let mut bcc = m.bcc.clone();
    let present: HashSet<String> = to
        .iter()
        .chain(&cc)
        .chain(&bcc)
        .map(|a| a.address.to_lowercase())
        .collect();
    for r in recipients {
        if !present.contains(&r.to_lowercase()) {
            bcc.push(Addr::new("", r.clone()));
        }
    }
    let body = match m.mime_type.as_str() {
        "text/html" => &m.rich_body,
        "text/plain" => &m.plain_body,
        _ => return Err(SubmitError::UnsupportedOutgoingMime),
    };
    let armored = ring.encrypt_armored(body.as_bytes(), false)?;
    let action = match (&m.in_reply_to, &m.forward_id) {
        (Some(irt), Some(fwd)) if irt == fwd => draft_action::FORWARD,
        (Some(_), _) => draft_action::REPLY,
        _ => draft_action::FORWARD,
    };
    let template = DraftTemplate {
        subject: m.subject.clone(),
        sender,
        to_list: to,
        cc_list: cc,
        bcc_list: bcc,
        body: armored,
        mime_type: m.mime_type.clone(),
        unread: false,
        external_id: m.external_id.clone(),
    };
    match ctx.client.create_draft(&template, parent, action).await {
        Ok(d) => Ok(d),
        Err(e) => Err(map_draft_error(e)),
    }
}

fn map_draft_error(e: Error) -> SubmitError {
    if let Some(a) = e.api()
        && a.status == 422
    {
        return match a.code {
            2001 => SubmitError::Malformed,
            2024 => SubmitError::TooLarge,
            2002 => SubmitError::InvalidRecipientList,
            _ => SubmitError::Other(e.to_string()),
        };
    }
    e.into()
}

/// Disposition normalisation (§13.11).
pub fn normalize_disposition(disposition: &str, content_id: Option<&str>) -> &'static str {
    match disposition {
        "inline" if content_id.is_none() => "attachment",
        "inline" => "inline",
        "attachment" => "attachment",
        _ if content_id.is_some() => "inline",
        _ => "attachment",
    }
}

/// Encrypt, sign and upload one attachment (§9.5), returning (ID, session
/// key).
pub async fn upload_attachment(
    ctx: &AccountContext,
    draft_id: &str,
    a: &OutAttachment,
    ring: &KeyRing,
) -> crate::Result<(String, SessionKey)> {
    let first = ring.first()?;
    let signature = first.sign_detached(&a.data)?;
    let (bin, _) = ring.encrypt(&a.data, false, &a.name)?;
    let (key_packets, data_packet) = crypto::split_message(&bin)?;
    let up = AttachmentUpload {
        message_id: draft_id.to_string(),
        filename: a.name.clone(),
        mime_type: a.mime_type.clone(),
        disposition: normalize_disposition(&a.disposition, a.content_id.as_deref()).to_string(),
        content_id: a.content_id.clone().unwrap_or_default(),
        key_packets,
        data_packet,
        signature,
    };
    let att = ctx.client.upload_attachment(&up).await?;
    let kp = b64_decode(&att.key_packets)?;
    let sk = ring.decrypt_session_key(&kp)?;
    Ok((att.id, sk))
}

async fn upload_attachments(
    ctx: &AccountContext,
    draft_id: &str,
    atts: &[OutAttachment],
    ring: &KeyRing,
) -> Result<BTreeMap<String, SessionKey>, SubmitError> {
    let futs = atts
        .iter()
        .map(|a| upload_attachment(ctx, draft_id, a, ring));
    let res = futures::future::try_join_all(futs).await?;
    Ok(res.into_iter().collect())
}

/// Check whether a reverse path or From address is owned.
pub fn is_owned(ctx: &AccountContext, email: &str) -> bool {
    ctx.addresses()
        .iter()
        .any(|a| canonical_email(&a.email) == canonical_email(email))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispositions() {
        assert_eq!(normalize_disposition("inline", None), "attachment");
        assert_eq!(normalize_disposition("inline", Some("x")), "inline");
        assert_eq!(normalize_disposition("", Some("x")), "inline");
        assert_eq!(normalize_disposition("weird", None), "attachment");
    }

    #[test]
    fn canonical() {
        let a = Address {
            email: "John.Doe@Example.org".into(),
            ..Default::default()
        };
        assert_eq!(
            canonical_sender("john.doe+news@example.org", &a),
            "John.Doe+news@Example.org"
        );
        assert_eq!(
            canonical_sender("john.doe@example.org", &a),
            "John.Doe@Example.org"
        );
    }

    #[test]
    fn error_texts() {
        assert_eq!(
            SubmitError::Throttled.smtp_reply(),
            "554 5.0.0 Error: Too many failed send attempts. Try again later"
        );
    }
}
