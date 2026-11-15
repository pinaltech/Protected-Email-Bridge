//! Message fingerprint (Appendix A), used to recognise the same message
//! across an SMTP submission and a later IMAP APPEND.

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::mime::{ContentType, Part, decode_cte, parse_address_list};
use crate::util::b64;

/// Compute the fingerprint of a raw RFC 5322 message.
pub fn message_fingerprint(literal: &[u8]) -> Result<String> {
    let root = Part::parse(literal).ok_or_else(|| Error::Mime("unparsable message".into()))?;
    Ok(fingerprint_part(&root))
}

/// Compute the fingerprint of an already parsed message.
pub fn fingerprint_part(root: &Part) -> String {
    let mut h = Sha256::new();
    h.update(root.header.get("Subject").unwrap_or_default().as_bytes());
    for f in ["From", "To", "Cc", "Reply-To", "In-Reply-To"] {
        let raw = root.header.get(f).unwrap_or_default();
        match parse_address_list(&raw) {
            Some(list) => {
                for a in list {
                    h.update(a.address.as_bytes());
                }
            }
            None => h.update(raw.as_bytes()),
        }
    }
    for leaf in root.leaves() {
        let ct_raw = leaf.header.get("Content-Type");
        let ct = ct_raw.as_deref().and_then(ContentType::parse);
        let mut is_text = false;
        if let Some(ct) = &ct {
            h.update(ct.value.as_bytes());
            let mut params: Vec<&(String, String)> = ct
                .params
                .iter()
                .filter(|(k, _)| !k.eq_ignore_ascii_case("boundary"))
                .collect();
            params.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            for (k, v) in params {
                h.update(k.as_bytes());
                h.update(v.as_bytes());
            }
            is_text = ct.value == "text/plain" || ct.value == "text/html";
        }
        h.update(
            leaf.header
                .get("Content-Disposition")
                .unwrap_or_default()
                .as_bytes(),
        );
        let body = if is_text {
            decode_cte(&leaf.body, &leaf.cte())
        } else {
            leaf.body.clone()
        };
        let no_cr: Vec<u8> = body.into_iter().filter(|&b| b != b'\r').collect();
        h.update(no_cr.trim_ascii());
    }
    b64(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_across_encodings() {
        let a = b"From: A <a@x.y>\r\nTo: b@x.y\r\nSubject: s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nhello world\r\n";
        let b = b"Subject: s\r\nTo: <b@x.y>\r\nFrom: a@x.y\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8gd29ybGQ=\r\n";
        assert_eq!(
            message_fingerprint(a).unwrap(),
            message_fingerprint(b).unwrap()
        );
    }
}
