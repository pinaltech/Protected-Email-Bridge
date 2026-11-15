//! Message retrieval, actions, drafts, send, attachments and import
//! endpoints (§8.6–§8.11).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::client::{ApiClient, FormPart, Request, check_code};
use super::types::*;
use crate::config::limits;
use crate::error::{ApiError, Error, Result};
use crate::util::null_default;

/// Message listing filter (§8.6).
#[derive(Debug, Clone, Default, Serialize)]
pub struct MessageFilter {
    #[serde(rename = "ID", skip_serializing_if = "Vec::is_empty")]
    pub ids: Vec<String>,
    #[serde(rename = "Subject", skip_serializing_if = "String::is_empty")]
    pub subject: String,
    #[serde(rename = "AddressID", skip_serializing_if = "String::is_empty")]
    pub address_id: String,
    #[serde(rename = "ExternalID", skip_serializing_if = "String::is_empty")]
    pub external_id: String,
    #[serde(rename = "LabelID", skip_serializing_if = "String::is_empty")]
    pub label_id: String,
    #[serde(rename = "EndID", skip_serializing_if = "String::is_empty")]
    pub end_id: String,
    #[serde(rename = "Desc", serialize_with = "ser_intbool")]
    pub desc: bool,
}

fn ser_intbool<S: serde::Serializer>(v: &bool, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_u8(u8::from(*v))
}

/// Draft template (§8.8).
#[derive(Debug, Clone, Default, Serialize)]
pub struct DraftTemplate {
    #[serde(rename = "Subject")]
    pub subject: String,
    #[serde(rename = "Sender")]
    pub sender: Addr,
    #[serde(rename = "ToList")]
    pub to_list: Vec<Addr>,
    #[serde(rename = "CCList")]
    pub cc_list: Vec<Addr>,
    #[serde(rename = "BCCList")]
    pub bcc_list: Vec<Addr>,
    /// Armored OpenPGP message (§9.4).
    #[serde(rename = "Body")]
    pub body: String,
    #[serde(rename = "MIMEType")]
    pub mime_type: String,
    #[serde(rename = "Unread", serialize_with = "ser_intbool")]
    pub unread: bool,
    #[serde(rename = "ExternalID", skip_serializing_if = "String::is_empty")]
    pub external_id: String,
}

/// Create-draft action codes (Appendix C.4).
pub mod draft_action {
    pub const REPLY: i64 = 0;
    pub const REPLY_ALL: i64 = 1;
    pub const FORWARD: i64 = 2;
    pub const AUTO_RESPONSE: i64 = 3;
    pub const READ_RECEIPT: i64 = 4;
}

/// A session key in JSON form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionKeyJson {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "Algorithm")]
    pub algorithm: String,
}

/// Per-recipient package entry (§8.9).
#[derive(Debug, Clone, Default, Serialize)]
pub struct PackageAddress {
    #[serde(rename = "Type")]
    pub scheme: i64,
    #[serde(rename = "Signature")]
    pub signature: i64,
    #[serde(rename = "BodyKeyPacket", skip_serializing_if = "Option::is_none")]
    pub body_key_packet: Option<String>,
    #[serde(
        rename = "AttachmentKeyPackets",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub attachment_key_packets: BTreeMap<String, String>,
}

/// One send package (§8.9).
#[derive(Debug, Clone, Default, Serialize)]
pub struct SendPackage {
    #[serde(rename = "Addresses")]
    pub addresses: BTreeMap<String, PackageAddress>,
    #[serde(rename = "MIMEType")]
    pub mime_type: String,
    #[serde(rename = "Type")]
    pub scheme: i64,
    #[serde(rename = "Body")]
    pub body: String,
    #[serde(rename = "BodyKey", skip_serializing_if = "Option::is_none")]
    pub body_key: Option<SessionKeyJson>,
    #[serde(rename = "AttachmentKeys", skip_serializing_if = "BTreeMap::is_empty")]
    pub attachment_keys: BTreeMap<String, SessionKeyJson>,
}

/// Attachment upload request (§8.10).
#[derive(Debug, Clone)]
pub struct AttachmentUpload {
    pub message_id: String,
    pub filename: String,
    pub mime_type: String,
    pub disposition: String,
    pub content_id: String,
    pub key_packets: Vec<u8>,
    pub data_packet: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Import metadata for one message (§8.11).
#[derive(Debug, Clone, Default, Serialize)]
pub struct ImportMetadata {
    #[serde(rename = "AddressID")]
    pub address_id: String,
    #[serde(rename = "LabelIDs")]
    pub label_ids: Vec<String>,
    #[serde(rename = "Unread", serialize_with = "ser_intbool")]
    pub unread: bool,
    #[serde(rename = "Flags")]
    pub flags: i64,
}

/// One message to import: the encrypted literal plus metadata.
#[derive(Debug, Clone)]
pub struct ImportRequest {
    pub literal: Vec<u8>,
    pub metadata: ImportMetadata,
}

#[derive(Deserialize)]
struct ItemResponse {
    #[serde(rename = "ID", default)]
    id: String,
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "Response")]
    response: ItemResult,
}

#[derive(Deserialize)]
struct ItemResult {
    #[serde(rename = "Code")]
    code: i64,
    #[serde(rename = "Error", default)]
    error: String,
    #[serde(rename = "MessageID", default)]
    message_id: String,
}

fn item_error(id: &str, r: &ItemResult) -> Error {
    Error::Api(ApiError {
        status: 200,
        code: r.code,
        message: format!("{id}: {}", r.error),
        details: None,
    })
}

/// True if this error is an HTTP 422 (message no longer exists, etc.).
pub fn is_unprocessable(e: &Error) -> bool {
    e.status() == Some(422)
}

impl ApiClient {
    /// Count messages matching a filter (§8.6, `"Limit": "0"`).
    pub async fn count_messages(&self, filter: &MessageFilter) -> Result<i64> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Total", default)]
            total: i64,
        }
        let mut body = serde_json::to_value(filter)?;
        body["Limit"] = json!("0");
        if let Some(o) = body.as_object_mut() {
            o.remove("Desc");
        }
        let req = Request::post("/mail/v4/messages")
            .header("X-HTTP-Method-Override", "GET")
            .json(body);
        Ok(self.send_json::<R>(req).await?.total)
    }

    /// List one page of message metadata (§8.6). Repeats while `Stale = 1`.
    pub async fn list_messages(
        &self,
        filter: &MessageFilter,
        page: usize,
        page_size: usize,
    ) -> Result<Vec<MessageMetadata>> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Messages", default, deserialize_with = "null_default")]
            messages: Vec<MessageMetadata>,
            #[serde(rename = "Stale", default, with = "crate::util::intbool")]
            stale: bool,
        }
        let mut body = serde_json::to_value(filter)?;
        body["Page"] = json!(page);
        body["PageSize"] = json!(page_size.min(limits::LIST_PAGE_SIZE));
        body["Sort"] = json!("ID");
        loop {
            let req = Request::post("/mail/v4/messages")
                .header("X-HTTP-Method-Override", "GET")
                .json(body.clone());
            let r: R = self.send_json(req).await?;
            if !r.stale {
                return Ok(r.messages);
            }
        }
    }

    /// List metadata for the given IDs (chunks of ≤ 150).
    pub async fn list_messages_by_id(
        &self,
        ids: &[String],
        address_id: Option<&str>,
    ) -> Result<Vec<MessageMetadata>> {
        let mut out = Vec::new();
        for chunk in ids.chunks(limits::LIST_PAGE_SIZE) {
            let filter = MessageFilter {
                ids: chunk.to_vec(),
                address_id: address_id.unwrap_or_default().to_string(),
                ..Default::default()
            };
            out.extend(
                self.list_messages(&filter, 0, limits::LIST_PAGE_SIZE)
                    .await?,
            );
        }
        Ok(out)
    }

    /// `GET /mail/v4/messages/{id}`. HTTP 422 means the message is gone.
    pub async fn get_message(&self, id: &str) -> Result<Message> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Message")]
            message: Message,
        }
        Ok(self
            .send_json::<R>(Request::get(format!("/mail/v4/messages/{id}")))
            .await?
            .message)
    }

    /// Enumerate every message ID (§8.6).
    pub async fn get_all_message_ids(&self) -> Result<Vec<String>> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "IDs", default, deserialize_with = "null_default")]
            ids: Vec<String>,
        }
        let mut out = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let mut req =
                Request::get("/mail/v4/messages/ids").query("Limit", limits::ID_ENUMERATION_PAGE);
            if let Some(a) = &after {
                req = req.query("AfterID", a);
            }
            let r: R = self.send_json(req).await?;
            if r.ids.is_empty() {
                return Ok(out);
            }
            after = r.ids.last().cloned();
            out.extend(r.ids);
        }
    }

    /// `GET /mail/v4/messages/count`.
    pub async fn get_message_counts(&self) -> Result<Vec<MessageCount>> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Counts", default, deserialize_with = "null_default")]
            counts: Vec<MessageCount>,
        }
        Ok(self
            .send_json::<R>(Request::get("/mail/v4/messages/count"))
            .await?
            .counts)
    }

    async fn simple_action(&self, action: &str, ids: &[String]) -> Result<()> {
        for chunk in ids.chunks(limits::BULK_ACTION_CHUNK) {
            self.send(
                Request::put(format!("/mail/v4/messages/{action}")).json(json!({ "IDs": chunk })),
            )
            .await?;
        }
        Ok(())
    }

    pub async fn mark_read(&self, ids: &[String]) -> Result<()> {
        self.simple_action("read", ids).await
    }

    pub async fn mark_unread(&self, ids: &[String]) -> Result<()> {
        self.simple_action("unread", ids).await
    }

    /// Permanently delete messages.
    pub async fn delete_messages(&self, ids: &[String]) -> Result<()> {
        self.simple_action("delete", ids).await
    }

    async fn multi_status_action(&self, action: &str, ids: &[String]) -> Result<()> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Responses", default, deserialize_with = "null_default")]
            responses: Vec<ItemResponse>,
        }
        for chunk in ids.chunks(limits::BULK_ACTION_CHUNK) {
            let raw = self
                .send(
                    Request::put(format!("/mail/v4/messages/{action}"))
                        .json(json!({ "IDs": chunk })),
                )
                .await?;
            let r: R = raw.json()?;
            if let Some(bad) = r.responses.iter().find(|i| i.response.code != 1000) {
                return Err(item_error(&bad.id, &bad.response));
            }
        }
        Ok(())
    }

    pub async fn mark_forwarded(&self, ids: &[String]) -> Result<()> {
        self.multi_status_action("forward", ids).await
    }

    pub async fn mark_unforwarded(&self, ids: &[String]) -> Result<()> {
        self.multi_status_action("unforward", ids).await
    }

    async fn label_action(&self, action: &str, label_id: &str, ids: &[String]) -> Result<()> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Responses", default, deserialize_with = "null_default")]
            responses: Vec<ItemResponse>,
            #[serde(rename = "UndoToken", default)]
            undo_token: Option<UndoToken>,
        }
        let mut undo: Vec<UndoToken> = Vec::new();
        for chunk in ids.chunks(limits::BULK_ACTION_CHUNK) {
            let res = self
                .send(
                    Request::put(format!("/mail/v4/messages/{action}"))
                        .json(json!({ "LabelID": label_id, "IDs": chunk })),
                )
                .await
                .and_then(|raw| raw.json::<R>());
            let failure = match res {
                Ok(r) => match r.responses.iter().find(|i| i.response.code != 1000) {
                    Some(bad) => Some(item_error(&bad.id, &bad.response)),
                    None => {
                        if let Some(t) = r.undo_token {
                            undo.push(t);
                        }
                        None
                    }
                },
                Err(e) => Some(e),
            };
            if let Some(err) = failure {
                // Undo every previously successful chunk (§8.7).
                let now = self.server_now();
                for t in undo.iter().filter(|t| t.valid_until > now) {
                    if let Err(e) = self.undo_action(t).await {
                        tracing::warn!("undo of label action failed: {e}");
                    }
                }
                return Err(err);
            }
        }
        Ok(())
    }

    /// Add a label to messages (with undo on partial failure).
    pub async fn label_messages(&self, label_id: &str, ids: &[String]) -> Result<()> {
        self.label_action("label", label_id, ids).await
    }

    /// Remove a label from messages (with undo on partial failure).
    pub async fn unlabel_messages(&self, label_id: &str, ids: &[String]) -> Result<()> {
        self.label_action("unlabel", label_id, ids).await
    }

    /// `POST /mail/v4/undoactions`.
    pub async fn undo_action(&self, token: &UndoToken) -> Result<Vec<Message>> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Messages", default, deserialize_with = "null_default")]
            messages: Vec<Message>,
        }
        Ok(self
            .send_json::<R>(Request::post("/mail/v4/undoactions").json(token))
            .await?
            .messages)
    }

    /// `POST /mail/v4/messages` — create a draft.
    pub async fn create_draft(
        &self,
        template: &DraftTemplate,
        parent_id: Option<&str>,
        action: i64,
    ) -> Result<Message> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Message")]
            message: Message,
        }
        let mut body = json!({
            "Message": template,
            "AttachmentKeyPackets": Value::Null,
            "Action": action,
        });
        if let Some(p) = parent_id.filter(|p| !p.is_empty()) {
            body["ParentID"] = json!(p);
        }
        Ok(self
            .send_json::<R>(Request::post("/mail/v4/messages").json(body))
            .await?
            .message)
    }

    /// `PUT /mail/v4/messages/{id}` — update a draft.
    pub async fn update_draft(&self, id: &str, template: &DraftTemplate) -> Result<Message> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Message")]
            message: Message,
        }
        let mut msg = serde_json::to_value(template)?;
        if template.body.is_empty()
            && let Some(o) = msg.as_object_mut()
        {
            o.remove("Body");
        }
        Ok(self
            .send_json::<R>(
                Request::put(format!("/mail/v4/messages/{id}"))
                    .json(json!({ "Message": msg, "AttachmentKeyPackets": Value::Null })),
            )
            .await?
            .message)
    }

    /// `POST /mail/v4/messages/{draftID}` — send.
    pub async fn send_draft(&self, draft_id: &str, packages: &[SendPackage]) -> Result<Message> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Sent")]
            sent: Message,
        }
        Ok(self
            .send_json::<R>(
                Request::post(format!("/mail/v4/messages/{draft_id}"))
                    .json(json!({ "Packages": packages })),
            )
            .await?
            .sent)
    }

    /// `POST /mail/v4/attachments` (§8.10).
    pub async fn upload_attachment(&self, up: &AttachmentUpload) -> Result<Attachment> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Attachment")]
            attachment: Attachment,
        }
        let parts = vec![
            FormPart::text("MessageID", &up.message_id),
            FormPart::text("Filename", &up.filename),
            FormPart::text("MIMEType", &up.mime_type),
            FormPart::text("Disposition", &up.disposition),
            FormPart::text("ContentID", &up.content_id),
            FormPart::file(
                "KeyPackets",
                "blob",
                "application/octet-stream",
                up.key_packets.clone(),
            ),
            FormPart::file(
                "DataPacket",
                "blob",
                "application/octet-stream",
                up.data_packet.clone(),
            ),
            FormPart::file(
                "Signature",
                "blob",
                "application/octet-stream",
                up.signature.clone(),
            ),
        ];
        Ok(self
            .send_json::<R>(Request::post("/mail/v4/attachments").multipart(parts))
            .await?
            .attachment)
    }

    /// `GET /mail/v4/attachments/{id}` — raw data packet.
    pub async fn get_attachment(&self, id: &str) -> Result<Vec<u8>> {
        Ok(self
            .send(Request::get(format!("/mail/v4/attachments/{id}")))
            .await?
            .body)
    }

    /// `POST /mail/v4/messages/import` (§8.11). Enforces the batch limits and
    /// returns one result per input, in input order.
    pub async fn import_messages(&self, reqs: &[ImportRequest]) -> Result<Vec<Result<String>>> {
        for r in reqs {
            if r.literal.len() as u64 > limits::IMPORT_MESSAGE_CAP {
                return Err(Error::Limit("message exceeds import size limit".into()));
            }
        }
        let mut results: Vec<Result<String>> = Vec::with_capacity(reqs.len());
        let mut start = 0;
        while start < reqs.len() {
            let mut end = start;
            let mut size = 0u64;
            while end < reqs.len()
                && end - start < limits::IMPORT_BATCH_MESSAGES
                && (end == start
                    || size + reqs[end].literal.len() as u64 <= limits::IMPORT_BATCH_BYTES)
            {
                size += reqs[end].literal.len() as u64;
                end += 1;
            }
            results.extend(self.import_batch(&reqs[start..end]).await?);
            start = end;
        }
        Ok(results)
    }

    async fn import_batch(&self, reqs: &[ImportRequest]) -> Result<Vec<Result<String>>> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Responses", default, deserialize_with = "null_default")]
            responses: Vec<ItemResponse>,
        }
        let mut parts = Vec::new();
        let mut meta = serde_json::Map::new();
        for (i, r) in reqs.iter().enumerate() {
            let name = i.to_string();
            let mut data = r.literal.clone();
            data.extend_from_slice(b"\r\n");
            parts.push(FormPart::file(
                name.clone(),
                format!("{name}.eml"),
                "message/rfc822",
                data,
            ));
            meta.insert(name, serde_json::to_value(&r.metadata)?);
        }
        parts.push(FormPart {
            name: "Metadata".into(),
            filename: None,
            content_type: Some("application/json".into()),
            data: serde_json::to_vec(&Value::Object(meta))?,
        });
        let raw = self
            .send(Request::post("/mail/v4/messages/import").multipart(parts))
            .await?;
        let v: Value = raw.json()?;
        check_code(&v)?;
        let r: R = serde_json::from_value(v)?;
        let mut out: Vec<Result<String>> = (0..reqs.len())
            .map(|_| Err(Error::Other("no import response for message".into())))
            .collect();
        for item in r.responses {
            if let Ok(idx) = item.name.parse::<usize>()
                && idx < out.len()
            {
                out[idx] = if item.response.code == 1000 {
                    Ok(item.response.message_id)
                } else {
                    Err(item_error(&item.name, &item.response))
                };
            }
        }
        Ok(out)
    }

    /// `GET /mail/v4/settings`.
    pub async fn get_mail_settings(&self) -> Result<MailSettings> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "MailSettings", default)]
            mail_settings: MailSettings,
        }
        Ok(self
            .send_json::<R>(Request::get("/mail/v4/settings"))
            .await?
            .mail_settings)
    }
}
