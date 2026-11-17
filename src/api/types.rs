//! Remote data model (§7).

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

use crate::util::{intbool, null_default};

/// `{"Name": S, "Address": S}`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Addr {
    #[serde(rename = "Name", default, deserialize_with = "null_default")]
    pub name: String,
    #[serde(rename = "Address", default, deserialize_with = "null_default")]
    pub address: String,
}

impl Addr {
    pub fn new(name: impl Into<String>, address: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            address: address.into(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.name.is_empty() && self.address.is_empty()
    }
}

/// Key object (§7.1).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Key {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(default, deserialize_with = "null_default")]
    pub private_key: String,
    #[serde(default, deserialize_with = "null_default")]
    pub token: String,
    #[serde(default, deserialize_with = "null_default")]
    pub signature: String,
    #[serde(default, with = "intbool")]
    pub primary: bool,
    #[serde(default, with = "intbool")]
    pub active: bool,
    #[serde(default)]
    pub flags: i64,
}

/// Per-product used space.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ProductUsedSpace {
    #[serde(default)]
    pub calendar: i64,
    #[serde(default)]
    pub contact: i64,
    #[serde(default)]
    pub drive: i64,
    #[serde(default)]
    pub mail: i64,
    #[serde(default)]
    pub pass: i64,
}

/// User (§7.1).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct User {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(default, deserialize_with = "null_default")]
    pub name: String,
    #[serde(default, deserialize_with = "null_default")]
    pub display_name: String,
    #[serde(default, deserialize_with = "null_default")]
    pub email: String,
    #[serde(default, deserialize_with = "null_default")]
    pub keys: Vec<Key>,
    #[serde(default)]
    pub used_space: i64,
    #[serde(default)]
    pub max_space: i64,
    #[serde(default)]
    pub max_upload: i64,
    #[serde(default)]
    pub credit: i64,
    #[serde(default, deserialize_with = "null_default")]
    pub currency: String,
    #[serde(default)]
    pub product_used_space: ProductUsedSpace,
}

pub mod address_status {
    pub const DISABLED: i64 = 0;
    pub const ENABLED: i64 = 1;
    pub const DELETING: i64 = 2;
}

pub mod address_type {
    pub const ORIGINAL: i64 = 1;
    pub const ALIAS: i64 = 2;
    pub const CUSTOM: i64 = 3;
    pub const PREMIUM: i64 = 4;
    pub const EXTERNAL: i64 = 5;
}

/// Address (§7.2).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Address {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(default, deserialize_with = "null_default")]
    pub email: String,
    #[serde(default, with = "intbool")]
    pub send: bool,
    #[serde(default, with = "intbool")]
    pub receive: bool,
    #[serde(default)]
    pub status: i64,
    #[serde(rename = "Type", default)]
    pub kind: i64,
    #[serde(default)]
    pub order: i64,
    #[serde(default, deserialize_with = "null_default")]
    pub display_name: String,
    #[serde(default, deserialize_with = "null_default")]
    pub keys: Vec<Key>,
}

impl Address {
    pub fn is_enabled(&self) -> bool {
        self.status == address_status::ENABLED
    }

    pub fn is_external(&self) -> bool {
        self.kind == address_type::EXTERNAL
    }

    /// External with `Send = 0`: can neither send nor be an import target.
    pub fn is_external_non_sending(&self) -> bool {
        self.is_external() && !self.send
    }
}

/// Sort addresses by ascending `Order` (§7.2).
pub fn sort_addresses(addrs: &mut [Address]) {
    addrs.sort_by_key(|a| a.order);
}

pub mod label_type {
    pub const LABEL: i64 = 1;
    pub const CONTACT_GROUP: i64 = 2;
    pub const FOLDER: i64 = 3;
    pub const SYSTEM: i64 = 4;
}

/// Reserved system label IDs (§7.3).
pub mod label_id {
    pub const INBOX: &str = "0";
    pub const ALL_DRAFTS: &str = "1";
    pub const ALL_SENT: &str = "2";
    pub const TRASH: &str = "3";
    pub const SPAM: &str = "4";
    pub const ALL_MAIL: &str = "5";
    pub const ARCHIVE: &str = "6";
    pub const SENT: &str = "7";
    pub const DRAFTS: &str = "8";
    pub const OUTBOX: &str = "9";
    pub const STARRED: &str = "10";
    pub const ALL_SCHEDULED: &str = "12";

    /// System labels exposed over IMAP.
    pub const EXPOSED_SYSTEM: &[&str] = &[
        INBOX,
        TRASH,
        SPAM,
        ALL_MAIL,
        ARCHIVE,
        SENT,
        DRAFTS,
        STARRED,
        ALL_SCHEDULED,
    ];
}

/// Label (§7.3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Label {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "ParentID", default, deserialize_with = "null_default")]
    pub parent_id: String,
    #[serde(default, deserialize_with = "null_default")]
    pub name: String,
    #[serde(default, deserialize_with = "null_default")]
    pub path: String,
    #[serde(default, deserialize_with = "null_default")]
    pub color: String,
    #[serde(rename = "Type", default)]
    pub kind: i64,
}

impl Label {
    /// A label is wanted if it is a user label, a folder, or an exposed
    /// system label (§7.3).
    pub fn is_wanted(&self) -> bool {
        match self.kind {
            label_type::LABEL | label_type::FOLDER => true,
            label_type::SYSTEM => label_id::EXPOSED_SYSTEM.contains(&self.id.as_str()),
            _ => false,
        }
    }
}

/// Message flag bits (§7.4).
pub mod message_flag {
    pub const RECEIVED: i64 = 1 << 0;
    pub const SENT: i64 = 1 << 1;
    pub const INTERNAL: i64 = 1 << 2;
    pub const E2E: i64 = 1 << 3;
    pub const AUTO: i64 = 1 << 4;
    pub const REPLIED: i64 = 1 << 5;
    pub const REPLIED_ALL: i64 = 1 << 6;
    pub const FORWARDED: i64 = 1 << 7;
    pub const AUTO_REPLIED: i64 = 1 << 8;
    pub const IMPORTED: i64 = 1 << 9;
    pub const OPENED: i64 = 1 << 10;
    pub const RECEIPT_SENT: i64 = 1 << 11;
    pub const NOTIFIED: i64 = 1 << 12;
    pub const TOUCHED: i64 = 1 << 13;
    pub const RECEIPT: i64 = 1 << 14;
    pub const RECEIPT_REQUEST: i64 = 1 << 16;
    pub const PUBLIC_KEY: i64 = 1 << 17;
    pub const SIGN: i64 = 1 << 18;
    pub const UNSUBSCRIBED: i64 = 1 << 19;
    pub const SCHEDULED_SEND: i64 = 1 << 20;
    pub const ALIAS: i64 = 1 << 21;
    pub const DMARC_PASS: i64 = 1 << 23;
    pub const SPF_FAIL: i64 = 1 << 24;
    pub const DKIM_FAIL: i64 = 1 << 25;
    pub const DMARC_FAIL: i64 = 1 << 26;
    pub const HAM_MANUAL: i64 = 1 << 27;
    pub const SPAM_AUTO: i64 = 1 << 28;
    pub const SPAM_MANUAL: i64 = 1 << 29;
    pub const PHISHING_AUTO: i64 = 1 << 30;
    pub const PHISHING_MANUAL: i64 = 1 << 31;
}

/// MessageMetadata (§7.4).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MessageMetadata {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "AddressID", default, deserialize_with = "null_default")]
    pub address_id: String,
    #[serde(rename = "LabelIDs", default, deserialize_with = "null_default")]
    pub label_ids: Vec<String>,
    #[serde(rename = "ExternalID", default, deserialize_with = "null_default")]
    pub external_id: String,
    #[serde(default, deserialize_with = "null_default")]
    pub subject: String,
    #[serde(default, deserialize_with = "null_default")]
    pub sender: Addr,
    #[serde(default, deserialize_with = "null_default")]
    pub to_list: Vec<Addr>,
    #[serde(rename = "CCList", default, deserialize_with = "null_default")]
    pub cc_list: Vec<Addr>,
    #[serde(rename = "BCCList", default, deserialize_with = "null_default")]
    pub bcc_list: Vec<Addr>,
    #[serde(default, deserialize_with = "null_default")]
    pub reply_tos: Vec<Addr>,
    #[serde(default)]
    pub flags: i64,
    #[serde(default)]
    pub time: i64,
    #[serde(default)]
    pub size: i64,
    #[serde(default, with = "intbool")]
    pub unread: bool,
    #[serde(default, with = "intbool")]
    pub is_replied: bool,
    #[serde(default, with = "intbool")]
    pub is_replied_all: bool,
    #[serde(default, with = "intbool")]
    pub is_forwarded: bool,
    #[serde(default)]
    pub num_attachments: i64,
}

impl MessageMetadata {
    /// Draft ⇔ neither Received nor Sent is set.
    pub fn is_draft(&self) -> bool {
        self.flags & (message_flag::RECEIVED | message_flag::SENT) == 0
    }
    pub fn is_sent(&self) -> bool {
        self.flags & message_flag::SENT != 0
    }
    pub fn is_received(&self) -> bool {
        self.flags & message_flag::RECEIVED != 0
    }
    pub fn is_seen(&self) -> bool {
        !self.unread
    }
    pub fn is_starred(&self) -> bool {
        self.label_ids.iter().any(|l| l == label_id::STARRED)
    }
    pub fn has_label(&self, id: &str) -> bool {
        self.label_ids.iter().any(|l| l == id)
    }
}

/// Ordered header map (`ParsedHeaders` / attachment `Headers`): the JSON key
/// order is significant; arrays denote several instances of a field.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedHeaders(pub Vec<(String, Vec<String>)>);

impl ParsedHeaders {
    /// Every field instance in order, flattened.
    pub fn fields(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .iter()
            .flat_map(|(k, vs)| vs.iter().map(move |v| (k.as_str(), v.as_str())))
    }
}

impl<'de> Deserialize<'de> for ParsedHeaders {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = ParsedHeaders;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object of header names to string or string arrays")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(ParsedHeaders::default())
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(ParsedHeaders::default())
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                #[derive(Deserialize)]
                #[serde(untagged)]
                enum OneOrMany {
                    One(String),
                    Many(Vec<String>),
                }
                let mut out = Vec::new();
                while let Some((k, v)) = map.next_entry::<String, OneOrMany>()? {
                    let vals = match v {
                        OneOrMany::One(s) => vec![s],
                        OneOrMany::Many(v) => v,
                    };
                    out.push((k, vals));
                }
                Ok(ParsedHeaders(out))
            }
        }
        d.deserialize_any(V)
    }
}

impl Serialize for ParsedHeaders {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut m = s.serialize_map(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            if v.len() == 1 {
                m.serialize_entry(k, &v[0])?;
            } else {
                m.serialize_entry(k, v)?;
            }
        }
        m.end()
    }
}

/// Attachment (§7.4).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Attachment {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(default, deserialize_with = "null_default")]
    pub name: String,
    #[serde(default)]
    pub size: i64,
    #[serde(rename = "MIMEType", default, deserialize_with = "null_default")]
    pub mime_type: String,
    #[serde(default, deserialize_with = "null_default")]
    pub disposition: String,
    #[serde(default)]
    pub headers: ParsedHeaders,
    #[serde(default, deserialize_with = "null_default")]
    pub key_packets: String,
    #[serde(default, deserialize_with = "null_default")]
    pub signature: String,
}

/// Full Message (§7.4).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Message {
    #[serde(flatten)]
    pub metadata: MessageMetadata,
    #[serde(default, deserialize_with = "null_default")]
    pub header: String,
    #[serde(default)]
    pub parsed_headers: ParsedHeaders,
    #[serde(default, deserialize_with = "null_default")]
    pub body: String,
    #[serde(rename = "MIMEType", default, deserialize_with = "null_default")]
    pub mime_type: String,
    #[serde(default, deserialize_with = "null_default")]
    pub attachments: Vec<Attachment>,
}

/// Mail settings (§7.5).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MailSettings {
    #[serde(default, deserialize_with = "null_default")]
    pub display_name: String,
    #[serde(default, deserialize_with = "null_default")]
    pub signature: String,
    #[serde(rename = "DraftMIMEType", default, deserialize_with = "null_default")]
    pub draft_mime_type: String,
    #[serde(default, with = "intbool")]
    pub attach_public_key: bool,
    #[serde(default)]
    pub sign: i64,
    #[serde(rename = "PGPScheme", default)]
    pub pgp_scheme: i64,
}

/// User settings (§8.12).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserSettings {
    #[serde(default)]
    pub telemetry: i64,
    #[serde(default)]
    pub crash_reports: i64,
}

/// ContactEmail (§7.6).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContactEmail {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(default, deserialize_with = "null_default")]
    pub name: String,
    #[serde(default, deserialize_with = "null_default")]
    pub email: String,
    #[serde(rename = "Type", default, deserialize_with = "null_default")]
    pub kind: Vec<String>,
    #[serde(rename = "ContactID", default, deserialize_with = "null_default")]
    pub contact_id: String,
    #[serde(rename = "LabelIDs", default, deserialize_with = "null_default")]
    pub label_ids: Vec<String>,
}

pub mod card_type {
    pub const CLEAR: i64 = 0;
    pub const ENCRYPTED: i64 = 1;
    pub const SIGNED: i64 = 2;
}

/// Card (§7.6).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Card {
    #[serde(rename = "Type", default)]
    pub kind: i64,
    #[serde(default, deserialize_with = "null_default")]
    pub data: String,
    #[serde(default, deserialize_with = "null_default")]
    pub signature: String,
}

/// Contact (§7.6).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Contact {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(default, deserialize_with = "null_default")]
    pub name: String,
    #[serde(rename = "UID", default, deserialize_with = "null_default")]
    pub uid: String,
    #[serde(default)]
    pub size: i64,
    #[serde(default)]
    pub create_time: i64,
    #[serde(default)]
    pub modify_time: i64,
    #[serde(default, deserialize_with = "null_default")]
    pub contact_emails: Vec<ContactEmail>,
    #[serde(rename = "LabelIDs", default, deserialize_with = "null_default")]
    pub label_ids: Vec<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub cards: Vec<Card>,
}

/// Event action codes (Appendix C.3).
pub mod event_action {
    pub const DELETE: i64 = 0;
    pub const CREATE: i64 = 1;
    pub const UPDATE: i64 = 2;
    pub const UPDATE_FLAGS: i64 = 3;
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MessageEvent {
    #[serde(rename = "ID")]
    pub id: String,
    pub action: i64,
    #[serde(default)]
    pub message: Option<MessageMetadata>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LabelEvent {
    #[serde(rename = "ID")]
    pub id: String,
    pub action: i64,
    #[serde(default)]
    pub label: Option<Label>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AddressEvent {
    #[serde(rename = "ID")]
    pub id: String,
    pub action: i64,
    #[serde(default)]
    pub address: Option<Address>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NotificationPayload {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub subtitle: String,
    #[serde(default)]
    pub body: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Notification {
    #[serde(rename = "ID", default)]
    pub id: String,
    #[serde(rename = "UID", default)]
    pub uid: String,
    #[serde(rename = "UserID", default)]
    pub user_id: String,
    /// What the notification is for, as text (`modal` for popups. It was parsed as a number, and the text the Service sends made
    /// every event carrying a notification fail, stalling the event loop at
    /// it; a number is still read, as its digits, should one come.
    #[serde(rename = "Type", default, deserialize_with = "text_or_number")]
    pub kind: String,
    #[serde(default)]
    pub time: i64,
    #[serde(default)]
    pub payload: NotificationPayload,
}

/// A string field that may also arrive as a number (or null).
fn text_or_number<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Text(String),
        Number(serde_json::Number),
        Null(()),
    }
    Ok(match Raw::deserialize(d)? {
        Raw::Text(t) => t,
        Raw::Number(n) => n.to_string(),
        Raw::Null(()) => String::new(),
    })
}

/// Event refresh bits (§7.7).
pub mod refresh_flag {
    pub const MAIL: i64 = 1;
    pub const ALL: i64 = 255;
}

/// Event (§7.7).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Event {
    #[serde(rename = "EventID")]
    pub event_id: String,
    #[serde(default)]
    pub refresh: i64,
    #[serde(default)]
    pub user: Option<User>,
    #[serde(default)]
    pub user_settings: Option<UserSettings>,
    #[serde(default)]
    pub mail_settings: Option<MailSettings>,
    #[serde(default, deserialize_with = "null_default")]
    pub messages: Vec<MessageEvent>,
    #[serde(default, deserialize_with = "null_default")]
    pub labels: Vec<LabelEvent>,
    #[serde(default, deserialize_with = "null_default")]
    pub addresses: Vec<AddressEvent>,
    #[serde(default, deserialize_with = "null_default")]
    pub notifications: Vec<Notification>,
    #[serde(default)]
    pub used_space: Option<i64>,
    #[serde(default, with = "intbool")]
    pub more: bool,
}

/// Undo token (§7.8).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UndoToken {
    pub token: String,
    pub valid_until: i64,
}

/// Key salt entry (§6.1).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct KeySalt {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(default, deserialize_with = "null_default")]
    pub key_salt: String,
}

pub mod public_key_flag {
    pub const TRUSTED: i64 = 1;
    pub const ACTIVE: i64 = 2;
}

pub mod recipient_type {
    pub const INTERNAL: i64 = 1;
    pub const EXTERNAL: i64 = 2;
}

/// Public key entry (§6.4).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PublicKeyEntry {
    #[serde(default)]
    pub flags: i64,
    #[serde(default)]
    pub public_key: String,
}

/// `GET /core/v4/keys?Email=` response (§6.4).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PublicKeys {
    #[serde(default, deserialize_with = "null_default")]
    pub keys: Vec<PublicKeyEntry>,
    #[serde(default)]
    pub recipient_type: i64,
}

/// Per-label message count (§8.6).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MessageCount {
    #[serde(rename = "LabelID")]
    pub label_id: String,
    #[serde(default)]
    pub total: i64,
    #[serde(default)]
    pub unread: i64,
}

/// Session listing entry (§5.5.3).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SessionInfo {
    #[serde(rename = "UID")]
    pub uid: String,
    #[serde(default)]
    pub create_time: i64,
    #[serde(rename = "ClientID", default)]
    pub client_id: String,
    #[serde(rename = "MemberID", default)]
    pub member_id: Option<String>,
    #[serde(default, with = "intbool")]
    pub revocable: bool,
    #[serde(default)]
    pub localized_client_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsed_headers_order() {
        let j = r#"{"Received":["a","b"],"Subject":"hi","From":"x"}"#;
        let h: ParsedHeaders = serde_json::from_str(j).unwrap();
        let f: Vec<_> = h.fields().collect();
        assert_eq!(
            f,
            vec![
                ("Received", "a"),
                ("Received", "b"),
                ("Subject", "hi"),
                ("From", "x")
            ]
        );
    }

    /// An event carrying a notification parses: its type is text.
    #[test]
    fn event_with_a_notification() {
        let j = r#"{"EventID":"e2","Refresh":0,"More":0,"Notifications":[{"ID":"n","UID":"u","UserID":"x","Type":"modal","Time":1700000000,"Payload":{"Title":"T","Subtitle":"S","Body":"B"}}]}"#;
        let e: Event = serde_json::from_str(j).unwrap();
        assert_eq!(e.event_id, "e2");
        let n = &e.notifications[0];
        assert_eq!(n.kind, "modal");
        assert_eq!((n.payload.title.as_str(), n.payload.body.as_str()), ("T", "B"));
        for (raw, kind) in [("7", "7"), ("null", "")] {
            let j = format!(r#"{{"ID":"n","Type":{raw}}}"#);
            let n: Notification = serde_json::from_str(&j).unwrap();
            assert_eq!(n.kind, kind);
        }
    }

    #[test]
    fn message_flatten() {
        let j = r#"{"ID":"m","LabelIDs":["0","10"],"Unread":1,"Flags":1,"Body":"x","MIMEType":"text/plain","ParsedHeaders":null}"#;
        let m: Message = serde_json::from_str(j).unwrap();
        assert!(m.metadata.unread);
        assert!(m.metadata.is_starred());
        assert!(!m.metadata.is_draft());
    }
}
