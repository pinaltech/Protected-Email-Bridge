//! Endpoints used by the mobile push-notification client profile (§14):
//! device registration, notification quick actions, and the fresh
//! message/conversation fetches made when a notification is opened.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::client::{ApiClient, Request, check_code};
use super::types::{Conversation, MessageMetadata, label_id};
use crate::error::{ApiError, Error, Result};
use crate::util::null_default;

/// `Accept-Language` of an Android cloud-messaging registration (§4.2).
pub const DEVICE_LOCALE_LANGUAGE: &str = "en";
/// `x-pm-locale` of an Android cloud-messaging registration (§4.2).
pub const DEVICE_LOCALE: &str = "en_US";

/// API code: the session is missing scopes (second factor pending, §14.3.3).
pub const CODE_MISSING_SCOPES: i64 = 9100;
/// API code: the conversation does not exist (§14.7.2).
pub const CODE_CONVERSATION_NOT_FOUND: i64 = 20052;

/// `POST /core/v4/devices` body (§14.3.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceRegistrationRequest {
    #[serde(rename = "DeviceToken")]
    pub device_token: String,
    #[serde(rename = "Environment")]
    pub environment: i64,
    /// ASCII-armored device public key. Always present in this profile.
    #[serde(rename = "PublicKey")]
    pub public_key: String,
    #[serde(rename = "PingNotificationStatus")]
    pub ping_notification_status: Option<i64>,
    #[serde(rename = "PushNotificationStatus")]
    pub push_notification_status: Option<i64>,
}

/// How a quick-action request is sent (§14.6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// One attempt, transport retries disabled, optionally bounded by a
    /// deadline (step 3).
    Immediate { deadline: Option<Duration> },
    /// The normal request path with transport retries (step 6).
    Normal,
}

/// True for HTTP 403 with code 9100 (§14.3.3).
pub fn is_missing_scopes(e: &Error) -> bool {
    matches!(e.api(), Some(a) if a.status == 403 && a.code == CODE_MISSING_SCOPES)
}

/// True for HTTP 422 with code 20052 (§14.7.2 step 3).
pub fn is_conversation_not_found(e: &Error) -> bool {
    matches!(e.api(), Some(a) if a.status == 422 && a.code == CODE_CONVERSATION_NOT_FOUND)
}

#[derive(Deserialize)]
struct ItemResponse {
    #[serde(rename = "ID", default)]
    id: String,
    #[serde(rename = "Response")]
    response: ItemResult,
}

#[derive(Deserialize)]
struct ItemResult {
    #[serde(rename = "Code")]
    code: i64,
    #[serde(rename = "Error", default)]
    error: String,
}

#[derive(Deserialize)]
struct MultiStatus {
    #[serde(rename = "Responses", default, deserialize_with = "null_default")]
    responses: Vec<ItemResponse>,
}

/// Fail if any per-item response reports a code other than 1000.
fn check_items(v: &Value) -> Result<()> {
    check_code(v)?;
    if !v.is_object() {
        // Empty body: success is the HTTP status (§8.7).
        return Ok(());
    }
    let r: MultiStatus = serde_json::from_value(v.clone())?;
    match r.responses.iter().find(|i| i.response.code != 1000) {
        Some(bad) => Err(Error::Api(ApiError {
            status: 200,
            code: bad.response.code,
            message: format!("{}: {}", bad.id, bad.response.error),
            details: None,
        })),
        None => Ok(()),
    }
}

impl ApiClient {
    /// `POST /core/v4/devices` (§14.3.2). Registrations for the Android
    /// cloud-messaging environment carry the locale headers of §4.2.
    pub async fn register_device(&self, req: &DeviceRegistrationRequest) -> Result<()> {
        let mut post = Request::post("/core/v4/devices").json(req);
        if req.environment == crate::push::Environment::AndroidCloudMessaging.code() {
            post = post
                .header("Accept-Language", DEVICE_LOCALE_LANGUAGE)
                .header("x-pm-locale", DEVICE_LOCALE);
        }
        let v: Value = self.send_json(post).await?;
        check_code(&v)
    }

    async fn send_delivery(&self, req: Request, delivery: Delivery) -> Result<Value> {
        let raw = match delivery {
            Delivery::Immediate { deadline } => self.send_single_attempt(req, deadline).await?,
            Delivery::Normal => self.send(req).await?,
        };
        if raw.body.is_empty() {
            return Ok(Value::Null);
        }
        raw.json()
    }

    /// Quick action "mark as read": `PUT /mail/v4/messages/read` with one ID
    /// (§14.6.1).
    pub async fn notification_mark_read(&self, message_id: &str, delivery: Delivery) -> Result<()> {
        let req = Request::put("/mail/v4/messages/read").json(json!({ "IDs": [message_id] }));
        let v = self.send_delivery(req, delivery).await?;
        check_items(&v)
    }

    /// Quick action "move": `PUT /mail/v4/messages/label` with `Action: 1`
    /// (§14.6.1). Undo tokens are ignored.
    pub async fn notification_move(
        &self,
        message_id: &str,
        label: &str,
        delivery: Delivery,
    ) -> Result<()> {
        let req = Request::put("/mail/v4/messages/label").json(json!({
            "Action": 1,
            "IDs": [message_id],
            "LabelID": label,
            "SpamAction": Value::Null,
        }));
        let v = self.send_delivery(req, delivery).await?;
        check_items(&v)
    }

    /// `GET /mail/v4/messages?ID[0]=<id>&Page=0` (§14.7.1 step 1). `None`
    /// when the Service returns no message.
    pub async fn get_message_metadata(&self, message_id: &str) -> Result<Option<MessageMetadata>> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Messages", default, deserialize_with = "null_default")]
            messages: Vec<MessageMetadata>,
        }
        let req = Request::get("/mail/v4/messages")
            .query("ID[0]", message_id)
            .query("Page", 0);
        let r: R = self.send_json(req).await?;
        Ok(r.messages.into_iter().find(|m| m.id == message_id))
    }

    /// `GET /mail/v4/conversations/{id}` (§14.7.2 step 2). `None` when the
    /// conversation no longer exists (HTTP 422 / 20052).
    pub async fn get_conversation(
        &self,
        conversation_id: &str,
    ) -> Result<Option<(Conversation, Vec<MessageMetadata>)>> {
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Conversation")]
            conversation: Conversation,
            #[serde(rename = "Messages", default, deserialize_with = "null_default")]
            messages: Vec<MessageMetadata>,
        }
        match self
            .send_json::<R>(Request::get(format!(
                "/mail/v4/conversations/{conversation_id}"
            )))
            .await
        {
            Ok(r) => Ok(Some((r.conversation, r.messages))),
            Err(e) if is_conversation_not_found(&e) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Target labels of the move quick actions (§14.6.1).
pub const ARCHIVE_LABEL: &str = label_id::ARCHIVE;
pub const TRASH_LABEL: &str = label_id::TRASH;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_body_sends_null_statuses() {
        let r = DeviceRegistrationRequest {
            device_token: "tok".into(),
            environment: 4,
            public_key: "-----BEGIN PGP PUBLIC KEY BLOCK-----".into(),
            ping_notification_status: None,
            push_notification_status: Some(1),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(
            v,
            json!({
                "DeviceToken": "tok",
                "Environment": 4,
                "PublicKey": "-----BEGIN PGP PUBLIC KEY BLOCK-----",
                "PingNotificationStatus": null,
                "PushNotificationStatus": 1
            })
        );
    }

    #[test]
    fn item_failures_are_errors() {
        assert!(
            check_items(
                &json!({"Code": 1001, "Responses": [{"ID": "a", "Response": {"Code": 1000}}]})
            )
            .is_ok()
        );
        assert!(
            check_items(
                &json!({"Responses": [{"ID": "a", "Response": {"Code": 2501, "Error": "x"}}]})
            )
            .is_err()
        );
        assert!(check_items(&Value::Null).is_ok());
    }

    use crate::push::test_support;
    use std::sync::Arc;

    #[tokio::test]
    async fn quick_action_requests() {
        let stub = test_support::start(Arc::new(|s| {
            if s.path.ends_with("/label") {
                (200, r#"{"Code":1001,"Responses":[{"ID":"m1","Response":{"Code":1000}}],"UndoToken":{"Token":"t","ValidUntil":1}}"#.into())
            } else {
                (200, r#"{"Code":1001,"Responses":[{"ID":"m1","Response":{"Code":1000}}]}"#.into())
            }
        }))
        .await;
        let c = test_support::client(&stub.base).await;
        let imm = Delivery::Immediate {
            deadline: Some(Duration::from_secs(5)),
        };
        c.notification_mark_read("m1", imm).await.unwrap();
        c.notification_move("m1", ARCHIVE_LABEL, Delivery::Normal)
            .await
            .unwrap();
        c.notification_move("m1", TRASH_LABEL, imm).await.unwrap();
        let seen = stub.seen.lock().unwrap().clone();
        assert_eq!(
            (seen[0].method.as_str(), seen[0].path.as_str()),
            ("PUT", "/mail/v4/messages/read")
        );
        assert_eq!(seen[0].body, json!({"IDs": ["m1"]}));
        assert_eq!(seen[1].path, "/mail/v4/messages/label");
        assert_eq!(
            seen[1].body,
            json!({"Action": 1, "IDs": ["m1"], "LabelID": "6", "SpamAction": null})
        );
        assert_eq!(seen[2].body["LabelID"], "3");
    }

    #[tokio::test]
    async fn immediate_attempt_is_single_and_bounded() {
        let stub = test_support::start_with_delay(
            Arc::new(|_| (503, r#"{"Code":503}"#.into())),
            Duration::from_millis(400),
        )
        .await;
        let c = test_support::client(&stub.base).await;
        let r = c
            .notification_mark_read(
                "m1",
                Delivery::Immediate {
                    deadline: Some(Duration::from_millis(100)),
                },
            )
            .await;
        assert!(matches!(r, Err(Error::Network(_))));
        // No deadline: one attempt, the 503 is not retried.
        let r = c
            .notification_mark_read("m1", Delivery::Immediate { deadline: None })
            .await;
        assert_eq!(r.unwrap_err().status(), Some(503));
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(stub.seen.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn open_fetches() {
        let stub = test_support::start(Arc::new(|s| {
            if s.path.starts_with("/mail/v4/messages?") {
                (200, r#"{"Messages":[{"ID":"m1","ConversationID":"c1","Unread":1}],"Total":1,"Stale":0}"#.into())
            } else if s.path == "/mail/v4/conversations/c1" {
                (200, r#"{"Code":1000,"Conversation":{"ID":"c1","Labels":[{"ID":"0"}]},"Messages":[{"ID":"m1"}]}"#.into())
            } else {
                (422, r#"{"Code":20052,"Error":"gone"}"#.into())
            }
        }))
        .await;
        let c = test_support::client(&stub.base).await;
        let m = c.get_message_metadata("m1").await.unwrap().unwrap();
        assert_eq!(m.conversation_id, "c1");
        assert!(m.unread);
        let (conv, msgs) = c.get_conversation("c1").await.unwrap().unwrap();
        assert!(conv.has_label("0") && msgs.len() == 1);
        assert!(c.get_conversation("gone").await.unwrap().is_none());
        let seen = stub.seen.lock().unwrap().clone();
        assert_eq!(seen[0].method, "GET");
        assert_eq!(seen[0].path, "/mail/v4/messages?ID%5B0%5D=m1&Page=0");
    }

    #[test]
    fn error_classification() {
        let e = Error::Api(ApiError {
            status: 403,
            code: 9100,
            message: String::new(),
            details: None,
        });
        assert!(is_missing_scopes(&e));
        let e = Error::Api(ApiError {
            status: 422,
            code: 20052,
            message: String::new(),
            details: None,
        });
        assert!(is_conversation_not_found(&e));
        assert!(!is_missing_scopes(&e));
    }
}
