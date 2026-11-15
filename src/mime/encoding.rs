//! Encodings used in MIME: RFC 2047 words, quoted-printable, Base64,
//! charsets, addresses and dates.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Utc};
use encoding_rs::Encoding;

use crate::api::types::Addr;

/// RFC 2047 Q-encode `s` as UTF-8 if it contains non-ASCII characters (or
/// characters that would break a header); otherwise return it unchanged.
pub fn q_encode_if_needed(s: &str) -> String {
    if s.is_ascii() && !s.contains("=?") && !s.contains(['\r', '\n']) {
        return s.to_string();
    }
    q_encode(s)
}

/// RFC 2047 Q-encode `s` as UTF-8, splitting into words of bounded length.
pub fn q_encode(s: &str) -> String {
    let mut words = Vec::new();
    let mut cur = String::new();
    for ch in s.chars() {
        let mut enc = String::new();
        let mut buf = [0u8; 4];
        for b in ch.encode_utf8(&mut buf).bytes() {
            match b {
                b' ' => enc.push('_'),
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'!' | b'*' | b'+' | b'-' | b'/' => {
                    enc.push(b as char)
                }
                _ => enc.push_str(&format!("={b:02X}")),
            }
        }
        if cur.len() + enc.len() > 60 {
            words.push(std::mem::take(&mut cur));
        }
        cur.push_str(&enc);
    }
    if !cur.is_empty() || words.is_empty() {
        words.push(cur);
    }
    words
        .into_iter()
        .map(|w| format!("=?UTF-8?Q?{w}?="))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Decode a byte string in the given charset. Resolution order (§9.6): the
/// WHATWG label (which covers the IANA names), then the name with a `cs`
/// prefix removed.
pub fn decode_charset(data: &[u8], charset: &str) -> Option<String> {
    let label = charset.trim().trim_matches('"');
    let enc = Encoding::for_label(label.as_bytes()).or_else(|| {
        let l = label.to_ascii_lowercase();
        l.strip_prefix("cs")
            .and_then(|r| Encoding::for_label(r.as_bytes()))
    })?;
    let (out, _, had_errors) = enc.decode(data);
    if had_errors && enc != encoding_rs::UTF_8 {
        return None;
    }
    Some(out.into_owned())
}

/// Heuristic decoding when the charset is unknown: UTF-8 if valid, else
/// Windows-1252.
pub fn decode_heuristic(data: &[u8]) -> String {
    match std::str::from_utf8(data) {
        Ok(s) => s.to_string(),
        Err(_) => encoding_rs::WINDOWS_1252.decode(data).0.into_owned(),
    }
}

/// Decode RFC 2047 encoded-words in a header value.
pub fn decode_rfc2047(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    let mut last_was_word = false;
    while let Some(start) = rest.find("=?") {
        let (before, after) = rest.split_at(start);
        let parsed = parse_encoded_word(after);
        match parsed {
            Some((decoded, consumed)) => {
                if !(last_was_word && before.trim().is_empty()) {
                    out.push_str(before);
                }
                out.push_str(&decoded);
                rest = &after[consumed..];
                last_was_word = true;
            }
            None => {
                out.push_str(before);
                out.push_str("=?");
                rest = &after[2..];
                last_was_word = false;
            }
        }
    }
    out.push_str(rest);
    out
}

fn parse_encoded_word(s: &str) -> Option<(String, usize)> {
    let inner = s.strip_prefix("=?")?;
    let q1 = inner.find('?')?;
    let charset = &inner[..q1];
    let charset = charset.split('*').next().unwrap_or(charset);
    let rest = &inner[q1 + 1..];
    let q2 = rest.find('?')?;
    let enc = &rest[..q2];
    let text_start = &rest[q2 + 1..];
    let end = text_start.find("?=")?;
    let text = &text_start[..end];
    let bytes = match enc.to_ascii_uppercase().as_str() {
        "B" => STANDARD
            .decode(text.trim())
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(text.trim()))
            .ok()?,
        "Q" => {
            let t = text.replace('_', " ");
            quoted_printable::decode(t.as_bytes(), quoted_printable::ParseMode::Robust).ok()?
        }
        _ => return None,
    };
    let decoded = decode_charset(&bytes, charset).unwrap_or_else(|| decode_heuristic(&bytes));
    let consumed = 2 + q1 + 1 + q2 + 1 + end + 2;
    Some((decoded, consumed))
}

/// Quoted-printable encode (CRLF line endings, soft breaks at 76 columns).
pub fn qp_encode(data: &[u8]) -> String {
    let encoded = quoted_printable::encode_to_str(data);
    // The crate emits CRLF for hard breaks already; normalise lone LFs.
    normalize_crlf(encoded.as_bytes())
        .into_iter()
        .map(char::from)
        .collect()
}

/// Quoted-printable decode (robust).
pub fn qp_decode(data: &[u8]) -> Vec<u8> {
    quoted_printable::decode(data, quoted_printable::ParseMode::Robust)
        .unwrap_or_else(|_| data.to_vec())
}

/// Base64 decode ignoring whitespace, padding and trailing bits.
pub fn b64_decode_lenient(data: &[u8]) -> Vec<u8> {
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
    const LENIENT: GeneralPurpose = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    );
    let clean: Vec<u8> = data
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    LENIENT.decode(&clean).unwrap_or_default()
}

/// Decode a body according to its Content-Transfer-Encoding.
pub fn decode_cte(body: &[u8], cte: &str) -> Vec<u8> {
    match cte.trim().to_ascii_lowercase().as_str() {
        "quoted-printable" => qp_decode(body),
        "base64" => b64_decode_lenient(body),
        _ => body.to_vec(),
    }
}

/// Convert lone LF to CRLF.
pub fn normalize_crlf(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 40);
    let mut prev = 0u8;
    for &b in data {
        if b == b'\n' && prev != b'\r' {
            out.push(b'\r');
        }
        out.push(b);
        prev = b;
    }
    out
}

fn needs_quoting(name: &str) -> bool {
    name.chars()
        .any(|c| "()<>[]:;@\\,.\"".contains(c) || c.is_control())
}

/// Format an address as an RFC 5322 mailbox, encoding the display name per
/// RFC 2047 when needed.
pub fn format_address(a: &Addr) -> String {
    if a.name.is_empty() {
        return format!("<{}>", a.address);
    }
    let name = if !a.name.is_ascii() {
        q_encode(&a.name)
    } else if needs_quoting(&a.name) {
        format!("\"{}\"", a.name.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        a.name.clone()
    };
    format!("{name} <{}>", a.address)
}

/// Comma-join a list of addresses.
pub fn format_address_list(list: &[Addr]) -> String {
    list.iter()
        .map(format_address)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Parse an address list header value. Returns `None` if the value is
/// non-empty but yields no valid mailbox, or a mailbox lacks an `@`.
pub fn parse_address_list(value: &str) -> Option<Vec<Addr>> {
    if value.trim().is_empty() {
        return Some(Vec::new());
    }
    let raw = format!("To: {}\r\n\r\n", value.replace(['\r', '\n'], " "));
    let msg = mail_parser::MessageParser::new().parse_headers(raw.as_bytes())?;
    let list = msg.to()?;
    let mut out = Vec::new();
    for m in list.mailboxes() {
        let addr = m.address()?.trim().to_string();
        if !addr.contains('@') || addr.contains(char::is_whitespace) {
            return None;
        }
        out.push(Addr {
            name: m.name().unwrap_or_default().trim().to_string(),
            address: addr,
        });
    }
    if out.is_empty() { None } else { Some(out) }
}

/// Lenient variant: tolerate invalid entries (drops them).
pub fn parse_address_list_lenient(value: &str) -> Vec<Addr> {
    if let Some(v) = parse_address_list(value) {
        return v;
    }
    value
        .split(',')
        .filter_map(|p| parse_address_list(p).and_then(|v| v.into_iter().next()))
        .collect()
}

/// Parse an RFC 5322 date.
pub fn parse_date(value: &str) -> Option<DateTime<Utc>> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }
    if let Ok(d) = DateTime::parse_from_rfc2822(v) {
        return Some(d.with_timezone(&Utc));
    }
    // Strip trailing comments such as "(UTC)" and retry.
    let stripped = v.split(" (").next().unwrap_or(v);
    if let Ok(d) = DateTime::parse_from_rfc2822(stripped) {
        return Some(d.with_timezone(&Utc));
    }
    let raw = format!("Date: {v}\r\n\r\n");
    let msg = mail_parser::MessageParser::new().parse_headers(raw.as_bytes())?;
    let d = msg.date()?;
    DateTime::from_timestamp(d.to_timestamp(), 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn q_roundtrip() {
        let e = q_encode("Grüße an alle");
        assert!(e.starts_with("=?UTF-8?Q?"));
        assert_eq!(decode_rfc2047(&e), "Grüße an alle");
        assert_eq!(q_encode_if_needed("plain"), "plain");
    }

    #[test]
    fn rfc2047_b() {
        assert_eq!(decode_rfc2047("=?utf-8?b?4pi6?= x"), "☺ x");
        assert_eq!(decode_rfc2047("=?UTF-8?Q?a?= =?UTF-8?Q?b?="), "ab");
    }

    #[test]
    fn addresses() {
        let l = parse_address_list("\"Doe, J\" <j@d.org>, x@y.z").unwrap();
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].name, "Doe, J");
        assert_eq!(l[1].address, "x@y.z");
        assert!(parse_address_list("not an address").is_none());
        assert_eq!(format_address(&l[0]), "\"Doe, J\" <j@d.org>");
    }

    #[test]
    fn dates() {
        assert!(parse_date("Sat, 20 Nov 2021 14:22:01 -0800").is_some());
        assert!(parse_date("garbage").is_none());
    }

    #[test]
    fn charsets() {
        assert_eq!(decode_charset(b"\xe9", "iso-8859-1").unwrap(), "é");
        assert_eq!(decode_charset(b"\xe9", "csISOLatin1").unwrap(), "é");
    }
}
