//! Notification payloads (§14.5) and their presentation model.
//!
//! Notification content is unauthenticated, advisory display data
//! (§14.4.3 step 3). It contains personal data, so `Debug` output redacts
//! every text field (§14.5.4, §15).

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::util::intbool;

/// The decrypted notification: `{"type": …, "data": {…}}` (§14.5.1).
/// Unknown `type` values fail to deserialise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum Notification {
    Email(EmailNotification),
    OpenUrl(OpenUrlNotification),
}

impl Notification {
    /// Parse decrypted plaintext (§14.4.3 steps 4 and 6).
    pub fn parse(plaintext: &[u8]) -> crate::Result<Self> {
        Ok(serde_json::from_slice(plaintext)?)
    }

    pub fn sender(&self) -> &Sender {
        match self {
            Notification::Email(e) => &e.sender,
            Notification::OpenUrl(o) => &o.sender,
        }
    }
}

/// `{"Name", "Address", "Group"}` (§14.5.4). PascalCase on the wire.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Sender {
    pub name: String,
    pub address: String,
    pub group: String,
}

impl std::fmt::Debug for Sender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sender(<redacted>)")
    }
}

/// The Android-only `action` of an `email` payload (§14.5.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum EmailAction {
    /// `message_created`, or absent.
    #[default]
    MessageCreated,
    /// `message_touched`: dismiss any notification for the message.
    MessageTouched,
    /// Any other value, kept verbatim. Accepted but not displayed.
    Other(String),
}

impl EmailAction {
    pub fn as_str(&self) -> &str {
        match self {
            EmailAction::MessageCreated => "message_created",
            EmailAction::MessageTouched => "message_touched",
            EmailAction::Other(s) => s,
        }
    }
}

impl Serialize for EmailAction {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for EmailAction {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(match Option::<String>::deserialize(d)?.as_deref() {
            None | Some("message_created") => EmailAction::MessageCreated,
            Some("message_touched") => EmailAction::MessageTouched,
            Some(other) => EmailAction::Other(other.to_string()),
        })
    }
}

/// `email` payload (§14.5.2).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailNotification {
    pub title: String,
    pub subtitle: String,
    /// The message subject.
    pub body: String,
    pub message_id: String,
    pub sender: Sender,
    pub badge: i64,
    pub large_icon: String,
    pub small_icon: String,
    #[serde(default, with = "intbool")]
    pub sound: bool,
    #[serde(default, with = "intbool")]
    pub vibrate: bool,
    #[serde(default)]
    pub action: EmailAction,
}

impl std::fmt::Debug for EmailNotification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailNotification")
            .field("message_id", &self.message_id)
            .field("action", &self.action)
            .field("badge", &self.badge)
            .finish_non_exhaustive()
    }
}

/// `open_url` payload (§14.5.3).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenUrlNotification {
    pub title: String,
    pub subtitle: String,
    pub body: String,
    pub url: String,
    pub sender: Sender,
    pub badge: i64,
    pub large_icon: String,
    pub small_icon: String,
    /// Correlation identifier; may be empty. Not a mail message reference.
    pub message_id: String,
    #[serde(default, with = "intbool")]
    pub sound: bool,
    #[serde(default, with = "intbool")]
    pub vibrate: bool,
}

impl std::fmt::Debug for OpenUrlNotification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenUrlNotification")
            .field("badge", &self.badge)
            .finish_non_exhaustive()
    }
}

/// True if `url` is an absolute `https` URL with a host (§14.5.3, §15).
pub fn is_safe_url(url: &str) -> bool {
    reqwest::Url::parse(url)
        .map(|u| u.scheme() == "https" && u.host_str().is_some_and(|h| !h.is_empty()))
        .unwrap_or(false)
}

/// What a client needs to present a notification (§14.5.5). All text must be
/// rendered as plain text, never as markup (§15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presentation {
    /// Show (or replace) the notification keyed by (Account, `message_id`).
    ShowEmail {
        subject: String,
        sender: Sender,
        message_id: String,
    },
    /// Dismiss the notification keyed by (Account, `message_id`).
    Dismiss { message_id: String },
    /// Show an informational notice. `url` is `None` if it is not `https`;
    /// tapping must then open nothing.
    ShowNotice {
        content: String,
        sender: Sender,
        url: Option<String>,
    },
    /// Accepted but not displayed (unknown `action`).
    Ignore,
}

impl Presentation {
    /// Map a parsed notification to its presentation (§14.5.2, §14.5.3).
    pub fn of(n: &Notification) -> Self {
        match n {
            Notification::Email(e) => match &e.action {
                EmailAction::MessageCreated => Presentation::ShowEmail {
                    subject: e.body.clone(),
                    sender: e.sender.clone(),
                    message_id: e.message_id.clone(),
                },
                EmailAction::MessageTouched => Presentation::Dismiss {
                    message_id: e.message_id.clone(),
                },
                EmailAction::Other(_) => Presentation::Ignore,
            },
            Notification::OpenUrl(o) => Presentation::ShowNotice {
                content: o.body.clone(),
                sender: o.sender.clone(),
                url: is_safe_url(&o.url).then(|| o.url.clone()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMAIL: &str = r#"{"type":"email","data":{"title":"t","subtitle":"s","body":"Subject",
        "messageId":"m1","sender":{"Name":"Ann","Address":"ann@x.org","Group":""},
        "badge":3,"largeIcon":"large_icon","smallIcon":"small_icon","sound":1}}"#;

    #[test]
    fn email_defaults_and_actions() {
        let n = Notification::parse(EMAIL.as_bytes()).unwrap();
        let Notification::Email(e) = &n else { panic!() };
        assert_eq!(e.action, EmailAction::MessageCreated);
        assert!(e.sound && !e.vibrate);
        assert_eq!(e.sender.address, "ann@x.org");
        assert_eq!(
            Presentation::of(&n),
            Presentation::ShowEmail {
                subject: "Subject".into(),
                sender: e.sender.clone(),
                message_id: "m1".into()
            }
        );

        let touched = EMAIL.replace(r#""sound":1"#, r#""action":"message_touched""#);
        let n = Notification::parse(touched.as_bytes()).unwrap();
        assert_eq!(
            Presentation::of(&n),
            Presentation::Dismiss {
                message_id: "m1".into()
            }
        );

        let other = EMAIL.replace(r#""sound":1"#, r#""action":"message_exploded""#);
        let n = Notification::parse(other.as_bytes()).unwrap();
        let Notification::Email(e) = &n else { panic!() };
        assert_eq!(e.action, EmailAction::Other("message_exploded".into()));
        assert_eq!(Presentation::of(&n), Presentation::Ignore);
    }

    #[test]
    fn open_url_and_url_policy() {
        let j = r#"{"type":"open_url","data":{"title":"t","subtitle":"s","body":"New sign-in",
            "url":"https://account.example/sessions","sender":{"Name":"","Address":"","Group":""},
            "badge":0,"largeIcon":"large_icon","smallIcon":"small_icon","messageId":""}}"#;
        let n = Notification::parse(j.as_bytes()).unwrap();
        match Presentation::of(&n) {
            Presentation::ShowNotice { url, content, .. } => {
                assert_eq!(url.as_deref(), Some("https://account.example/sessions"));
                assert_eq!(content, "New sign-in");
            }
            p => panic!("{p:?}"),
        }
        let n = Notification::parse(j.replace("https://", "http://").as_bytes()).unwrap();
        assert!(matches!(
            Presentation::of(&n),
            Presentation::ShowNotice { url: None, .. }
        ));
        assert!(!is_safe_url("javascript:alert(1)"));
        assert!(!is_safe_url("/relative"));
    }

    #[test]
    fn rejects_unknown_type_and_missing_fields() {
        assert!(Notification::parse(br#"{"type":"promo","data":{}}"#).is_err());
        let missing = EMAIL.replace(r#""messageId":"m1","#, "");
        assert!(Notification::parse(missing.as_bytes()).is_err());
        assert!(Notification::parse(b"not json").is_err());
    }

    #[test]
    fn debug_redacts_personal_data() {
        let n = Notification::parse(EMAIL.as_bytes()).unwrap();
        let d = format!("{n:?}");
        assert!(!d.contains("ann@x.org") && !d.contains("Ann") && !d.contains("Subject"));
    }
}
