//! IMAP mailbox model (§11.5–§11.7): naming, attributes, flags, visibility,
//! UIDVALIDITY generation and modified UTF-7.

use std::collections::HashMap;

use base64::Engine;
use std::sync::Mutex;

use crate::api::types::{Label, label_id, label_type};
use crate::config::limits::UIDVALIDITY_EPOCH;
use crate::error::{Error, Result};

/// Hierarchy delimiter.
pub const DELIMITER: char = '/';
pub const FOLDERS: &str = "Folders";
pub const LABELS: &str = "Labels";

/// Local ID of the placeholder mailboxes and the recovery mailbox.
pub const FOLDERS_ID: &str = "\u{0}folders";
pub const LABELS_ID: &str = "\u{0}labels";
pub const RECOVERY_ID: &str = "\u{0}recovery";

/// The kind of a mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxKind {
    System,
    Folder,
    Label,
    Placeholder,
    Recovery,
}

/// Compute the mailbox name components for a Service label (§11.5.1).
/// `labels` is used to resolve folder paths through `ParentID`.
pub fn mailbox_name(label: &Label, labels: &HashMap<String, Label>) -> Option<Vec<String>> {
    match label.kind {
        label_type::SYSTEM => {
            if label.id == label_id::ALL_SCHEDULED {
                Some(vec!["Scheduled".into()])
            } else if label.name.eq_ignore_ascii_case("inbox") {
                Some(vec!["INBOX".into()])
            } else {
                Some(vec![label.name.clone()])
            }
        }
        label_type::FOLDER => {
            let mut v = vec![FOLDERS.to_string()];
            v.extend(folder_path(label, labels));
            Some(v)
        }
        label_type::LABEL => Some(vec![LABELS.to_string(), label_path(label)]),
        _ => None,
    }
}

fn label_path(label: &Label) -> String {
    if label.path.is_empty() {
        label.name.clone()
    } else {
        label.path.clone()
    }
}

/// Folder path segments, preferring `Path`, falling back to the ParentID
/// chain.
pub fn folder_path(label: &Label, labels: &HashMap<String, Label>) -> Vec<String> {
    if !label.path.is_empty() {
        return label.path.split('/').map(str::to_string).collect();
    }
    let mut segs = vec![label.name.clone()];
    let mut cur = label.parent_id.clone();
    let mut guard = 0;
    while !cur.is_empty() && guard < 64 {
        match labels.get(&cur) {
            Some(p) => {
                segs.push(p.name.clone());
                cur = p.parent_id.clone();
            }
            None => break,
        }
        guard += 1;
    }
    segs.reverse();
    segs
}

/// Mailbox attributes (§11.5.2).
pub fn attributes(kind: &MailboxKind, label_id: &str) -> Vec<&'static str> {
    match kind {
        MailboxKind::System => {
            let mut v = vec!["\\Noinferiors"];
            match label_id {
                label_id::TRASH => v.push("\\Trash"),
                label_id::SPAM => v.push("\\Junk"),
                label_id::ALL_MAIL => v.push("\\All"),
                label_id::ARCHIVE => v.push("\\Archive"),
                label_id::SENT => v.push("\\Sent"),
                label_id::DRAFTS => v.push("\\Drafts"),
                label_id::STARRED => v.push("\\Flagged"),
                _ => {}
            }
            v
        }
        MailboxKind::Placeholder => vec!["\\Noselect"],
        MailboxKind::Recovery => vec!["\\Noinferiors"],
        MailboxKind::Folder | MailboxKind::Label => vec![],
    }
}

/// FLAGS / PERMANENTFLAGS of a mailbox (§11.5.4, §11.11).
pub fn mailbox_flags(kind: &MailboxKind, label_id: &str) -> &'static [&'static str] {
    if *kind == MailboxKind::Recovery {
        &["\\Seen", "\\Flagged", "\\Deleted"]
    } else if label_id == label_id::ALL_MAIL {
        &["\\Seen", "\\Flagged"]
    } else {
        &[
            "\\Seen",
            "\\Flagged",
            "\\Deleted",
            "$Forwarded",
            "Forwarded",
        ]
    }
}

/// Visibility rule (§11.5.3).
pub fn is_visible(label_id: &str, show_all_mail: bool, message_count: usize) -> bool {
    match label_id {
        label_id::ALL_MAIL => show_all_mail,
        label_id::ALL_SCHEDULED => message_count > 0,
        _ => true,
    }
}

/// Strictly increasing UIDVALIDITY generator (§11.7).
#[derive(Debug, Default)]
pub struct UidValidityGenerator {
    last: Mutex<u32>,
}

impl UidValidityGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn next(&self) -> Result<u32> {
        let now = crate::util::now_unix() - UIDVALIDITY_EPOCH;
        let now = u32::try_from(now.max(1)).map_err(|_| Error::Limit("UIDVALIDITY".into()))?;
        let mut last = self.last.lock().expect("uidvalidity lock");
        let v = if now > *last {
            now
        } else {
            last.checked_add(1)
                .ok_or_else(|| Error::Limit("UIDVALIDITY".into()))?
        };
        *last = v;
        Ok(v)
    }
}

const MUTF7: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &match base64::alphabet::Alphabet::new(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,",
    ) {
        Ok(a) => a,
        Err(_) => panic!("alphabet"),
    },
    base64::engine::GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireNone),
);

/// Encode a mailbox name as modified UTF-7 (RFC 3501 §5.1.3).
pub fn utf7_encode(s: &str) -> String {
    let mut out = String::new();
    let mut pending: Vec<u16> = Vec::new();
    let flush = |pending: &mut Vec<u16>, out: &mut String| {
        if pending.is_empty() {
            return;
        }
        let bytes: Vec<u8> = pending.iter().flat_map(|u| u.to_be_bytes()).collect();
        out.push('&');
        out.push_str(&MUTF7.encode(bytes));
        out.push('-');
        pending.clear();
    };
    for c in s.chars() {
        if (' '..='~').contains(&c) {
            flush(&mut pending, &mut out);
            if c == '&' {
                out.push_str("&-");
            } else {
                out.push(c);
            }
        } else {
            let mut buf = [0u16; 2];
            pending.extend_from_slice(c.encode_utf16(&mut buf));
        }
    }
    flush(&mut pending, &mut out);
    out
}

/// Decode a modified UTF-7 mailbox name.
pub fn utf7_decode(s: &str) -> Result<String> {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let end = after
            .find('-')
            .ok_or_else(|| Error::Invalid("unterminated modified UTF-7".into()))?;
        let enc = &after[..end];
        if enc.is_empty() {
            out.push('&');
        } else {
            let bytes = MUTF7
                .decode(enc)
                .map_err(|_| Error::Invalid("bad modified UTF-7".into()))?;
            let units: Vec<u16> = bytes
                .chunks(2)
                .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                .collect();
            out.push_str(
                &String::from_utf16(&units)
                    .map_err(|_| Error::Invalid("bad UTF-16 in mailbox name".into()))?,
            );
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Normalise a client-supplied mailbox name: decode modified UTF-7 and match
/// an `INBOX` prefix case-insensitively (§11.3).
pub fn normalize_name(wire: &str) -> Result<Vec<String>> {
    let decoded = utf7_decode(wire)?;
    let mut parts: Vec<String> = decoded
        .split(DELIMITER)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect();
    if let Some(first) = parts.first_mut()
        && first.eq_ignore_ascii_case("INBOX")
    {
        *first = "INBOX".into();
    }
    Ok(parts)
}

/// Join name components for display on the wire (modified UTF-7).
pub fn wire_name(parts: &[String]) -> String {
    utf7_encode(&parts.join(&DELIMITER.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf7() {
        let n = "Entwürfe & Co/日本語";
        let e = utf7_encode(n);
        assert_eq!(utf7_decode(&e).unwrap(), n);
        assert_eq!(utf7_encode("a&b"), "a&-b");
        assert_eq!(
            utf7_decode("~peter/mail/&U,BTFw-/&ZeVnLIqe-").unwrap(),
            "~peter/mail/台北/日本語"
        );
    }

    #[test]
    fn names() {
        let mut labels = HashMap::new();
        let parent = Label {
            id: "p".into(),
            name: "Work".into(),
            kind: 3,
            ..Default::default()
        };
        labels.insert("p".into(), parent);
        let child = Label {
            id: "c".into(),
            name: "2024".into(),
            parent_id: "p".into(),
            kind: 3,
            ..Default::default()
        };
        assert_eq!(
            mailbox_name(&child, &labels).unwrap(),
            vec!["Folders", "Work", "2024"]
        );
        let inbox = Label {
            id: "0".into(),
            name: "Inbox".into(),
            kind: 4,
            ..Default::default()
        };
        assert_eq!(mailbox_name(&inbox, &labels).unwrap(), vec!["INBOX"]);
        assert_eq!(normalize_name("inbox").unwrap(), vec!["INBOX"]);
    }

    #[test]
    fn uidvalidity_increasing() {
        let g = UidValidityGenerator::new();
        let a = g.next().unwrap();
        let b = g.next().unwrap();
        assert!(b > a);
    }
}
