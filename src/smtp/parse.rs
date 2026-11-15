//! MIME parsing and normalisation of outgoing messages (§13.8).

use crate::api::types::Addr;
use crate::error::{Error, Result};
use crate::mime::{
    ContentType, Header, Part, decode_charset, decode_heuristic, decode_rfc2047,
    parse_address_list, parse_address_list_lenient, q_encode_if_needed,
};
use crate::util::strip_angles;

/// An attachment extracted from an outgoing message.
#[derive(Debug, Clone)]
pub struct OutAttachment {
    pub name: String,
    /// Media type with original parameters except `name`/`filename`.
    pub mime_type: String,
    pub content_id: Option<String>,
    /// Raw disposition value (`inline`, `attachment` or empty).
    pub disposition: String,
    pub data: Vec<u8>,
}

/// The extracted message model.
#[derive(Debug, Clone, Default)]
pub struct ParsedMessage {
    pub root: Part,
    pub subject: String,
    pub from: Option<Addr>,
    pub to: Vec<Addr>,
    pub cc: Vec<Addr>,
    pub bcc: Vec<Addr>,
    pub reply_to: Vec<Addr>,
    pub external_id: String,
    pub in_reply_to: Option<String>,
    pub forward_id: Option<String>,
    pub references: Vec<String>,
    pub attachments: Vec<OutAttachment>,
    pub rich_body: String,
    pub plain_body: String,
    /// `text/html` or `text/plain`.
    pub mime_type: String,
    /// The whole normalised message re-serialised.
    pub mime_body: Vec<u8>,
}

/// Trim a trailing `\r\n.\r\n` end-of-data marker (rule 1).
pub fn trim_end_of_data(data: &[u8]) -> &[u8] {
    data.strip_suffix(b"\r\n.\r\n")
        .map(|d| &data[..d.len() + 2])
        .unwrap_or(data)
}

fn is_attachment_disposition(p: &Part) -> bool {
    p.disposition().is_some_and(|d| d.value == "attachment")
}

/// Rewrite `<meta charset=...>` and `<meta content="...; charset=...">` to
/// UTF-8. Returns `None` if nothing changed.
fn rewrite_meta_charset(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let mut out = String::with_capacity(html.len());
    let mut changed = false;
    let mut pos = 0;
    while let Some(i) = lower[pos..].find("<meta") {
        let start = pos + i;
        let Some(end_rel) = lower[start..].find('>') else {
            break;
        };
        let end = start + end_rel;
        out.push_str(&html[pos..start]);
        let tag = &html[start..end];
        let ltag = &lower[start..end];
        if let Some(ci) = ltag.find("charset=") {
            let vstart = ci + "charset=".len();
            let bytes = tag.as_bytes();
            let mut vs = vstart;
            let quote = bytes.get(vs).copied().filter(|b| *b == b'"' || *b == b'\'');
            if quote.is_some() {
                vs += 1;
            }
            let mut ve = vs;
            while ve < bytes.len() && !matches!(bytes[ve], b'"' | b'\'' | b' ' | b';' | b'/' | b'>')
            {
                ve += 1;
            }
            if !tag[vs..ve].eq_ignore_ascii_case("utf-8") {
                changed = true;
            }
            out.push_str(&tag[..vs]);
            out.push_str("UTF-8");
            out.push_str(&tag[ve..]);
        } else {
            out.push_str(tag);
        }
        pos = end;
    }
    out.push_str(&html[pos..]);
    changed.then_some(out)
}

/// Rule 3: convert text parts to UTF-8.
fn normalise_charsets(p: &mut Part) {
    p.visit_mut(&mut |part: &mut Part| {
        if part.is_multipart() {
            return;
        }
        let ct = part.content_type();
        if ct.main_type() != "text" {
            return;
        }
        let is_html = ct.value == "text/html";
        if !is_html && is_attachment_disposition(part) {
            return;
        }
        let raw = part.decoded_body();
        let mut text = match ct.param("charset") {
            Some(cs) => decode_charset(&raw, cs).unwrap_or_else(|| decode_heuristic(&raw)),
            None => decode_heuristic(&raw),
        };
        if is_html && let Some(t) = rewrite_meta_charset(&text) {
            text = t;
        }
        let mut new_ct = ct.clone();
        new_ct.set_param("charset", "UTF-8");
        part.header.set("Content-Type", &new_ct.to_string());
        let cte = if text.is_ascii() {
            "quoted-printable"
        } else {
            "base64"
        };
        part.set_body(text.as_bytes(), cte);
    });
}

fn plain_to_html(text: &str) -> String {
    let esc = text
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace("\r\n", "\n")
        .replace('\n', "<br/>");
    format!("<p>{esc}</p>")
}

fn html_leaf(html: &str) -> Part {
    let mut h = Header::new();
    h.set("Content-Type", "text/html; charset=UTF-8");
    let mut p = Part::leaf(h, Vec::new());
    p.set_body(
        html.as_bytes(),
        if html.is_ascii() {
            "quoted-printable"
        } else {
            "base64"
        },
    );
    p
}

/// Rule 4: inline image patch on top-level children.
fn inline_image_patch(root: &mut Part) {
    if !root.is_multipart() || root.children.len() < 2 {
        return;
    }
    let mut patched = false;
    let mut i = 0;
    while i < root.children.len() {
        let c = &root.children[i];
        let ct = c.content_type();
        let disp = c.disposition();
        let is_inline = match &disp {
            Some(d) => d.value == "inline",
            None => c.content_id().is_some(),
        };
        if ct.main_type() == "image" && is_inline && c.content_id().is_none() {
            let cid = uuid::Uuid::new_v4().to_string();
            root.children[i]
                .header
                .set("Content-Id", &format!("<{cid}>"));
            let img = format!("<img src=\"cid:{cid}\"/>");
            let prev_plain = i > 0 && root.children[i - 1].content_type().value == "text/plain";
            if prev_plain {
                let txt = root.children[i - 1].text();
                root.children[i - 1] = html_leaf(&format!(
                    "<html><body>{}{img}</body></html>",
                    plain_to_html(&txt)
                ));
            } else {
                root.children
                    .insert(i, html_leaf(&format!("<html><body>{img}</body></html>")));
                i += 1;
            }
            patched = true;
        }
        i += 1;
    }
    if patched {
        for c in root.children.iter_mut() {
            if c.content_type().value == "text/plain" && !is_attachment_disposition(c) {
                let txt = c.text();
                *c = html_leaf(&format!(
                    "<html><body>{}</body></html>",
                    plain_to_html(&txt)
                ));
            }
        }
    }
}

fn ext_for(mime: &str) -> Option<&'static str> {
    Some(match mime {
        "text/plain" => ".txt",
        "text/html" => ".html",
        "text/calendar" => ".ics",
        "image/png" => ".png",
        "image/jpeg" => ".jpg",
        "image/gif" => ".gif",
        "application/pdf" => ".pdf",
        "application/zip" => ".zip",
        "application/pgp-keys" => ".asc",
        _ => return None,
    })
}

/// Rule 6: collect attachments (tree walk; first matching rule wins).
fn collect_attachments(p: &Part, out: &mut Vec<OutAttachment>) {
    if p.is_multipart() {
        for c in &p.children {
            collect_attachments(c, out);
        }
        return;
    }
    let ct = p.content_type();
    // Rules 6.1–6.4: attachment disposition, text/calendar, other leaves.
    let is_att =
        is_attachment_disposition(p) || ct.value == "text/calendar" || ct.main_type() != "text";
    if !is_att {
        return;
    }
    let disp = p.disposition();
    let name = disp
        .as_ref()
        .and_then(|d| d.param("filename").map(str::to_string))
        .or_else(|| ct.param("name").map(str::to_string))
        .map(|n| decode_rfc2047(&n))
        .unwrap_or_else(|| {
            if ct.value == "message/rfc822" {
                "message.eml".into()
            } else if let Some(ext) = ext_for(&ct.value) {
                format!("attachment{ext}")
            } else {
                "attachment.bin".into()
            }
        });
    let content_id = match &disp {
        Some(d) if d.value == "inline" => p.content_id(),
        None => p.content_id(),
        _ => None,
    };
    let mut mt = if p
        .header
        .get("Content-Type")
        .is_some_and(|v| !v.trim().is_empty())
    {
        ct.clone()
    } else {
        ContentType::new("text/plain")
    };
    mt.remove_param("name");
    mt.remove_param("filename");
    out.push(OutAttachment {
        name,
        mime_type: mt.to_string(),
        content_id,
        disposition: disp.map(|d| d.value).unwrap_or_default(),
        data: p.decoded_body(),
    });
}

/// Rule 7 helper: walk bodies preferring `pref` within alternatives.
fn collect_bodies(p: &Part, prefer_html: bool, out: &mut Vec<(String, String)>) {
    if p.is_multipart() {
        if p.content_type().sub_type() == "alternative" {
            let want = if prefer_html {
                "text/html"
            } else {
                "text/plain"
            };
            let pick = p
                .children
                .iter()
                .rev()
                .find(|c| c.leaves().iter().all(|l| l.content_type().value == want))
                .or_else(|| p.children.last());
            if let Some(c) = pick {
                collect_bodies(c, prefer_html, out);
            }
        } else {
            for c in &p.children {
                collect_bodies(c, prefer_html, out);
            }
        }
        return;
    }
    let ct = p.content_type();
    if ct.main_type() == "text" && ct.value != "text/calendar" && !is_attachment_disposition(p) {
        out.push((ct.value.clone(), p.text()));
    }
}

fn has_html(p: &Part) -> bool {
    p.leaves()
        .iter()
        .any(|l| l.content_type().value == "text/html" && !is_attachment_disposition(l))
}

/// Rule 7: re-encode any part with octets ≥ 0x80 as base64.
fn reencode_8bit(p: &mut Part) {
    p.visit_mut(&mut |part: &mut Part| {
        if !part.is_multipart() && part.body.iter().any(|b| *b >= 0x80) {
            let decoded = part.decoded_body();
            part.set_body(&decoded, "base64");
        }
    });
}

/// Rule 8: whether the message lacks a text part.
pub fn has_no_text_part(root: &Part) -> bool {
    let ct = root.content_type();
    if ct.value == "multipart/mixed" {
        !root.children.iter().any(|c| {
            c.header.get("Content-Disposition").is_none() && c.content_type().main_type() == "text"
        })
    } else {
        ct.main_type() != "text"
    }
}

/// Rule 9: add a child; a non-multipart/mixed root is first moved into a
/// new first child.
pub fn add_child(root: &mut Part, child: Part) {
    if root.content_type().value != "multipart/mixed" {
        let mut first_h = Header::new();
        for name in [
            "Content-Type",
            "Content-Disposition",
            "Content-Transfer-Encoding",
        ] {
            if let Some(v) = root.header.get(name) {
                first_h.set(name, &v);
                root.header.remove(name);
            }
        }
        let first = Part {
            header: first_h,
            body: std::mem::take(&mut root.body),
            children: std::mem::take(&mut root.children),
            boundary: root.boundary.take(),
            preamble: std::mem::take(&mut root.preamble),
            epilogue: std::mem::take(&mut root.epilogue),
        };
        let b = crate::util::mime_boundary();
        root.header
            .set("Content-Type", &format!("multipart/mixed; boundary={b}"));
        root.boundary = Some(b);
        root.children = vec![first];
    }
    root.children.push(child);
}

/// Rule 8: append an empty text part when there is none.
pub fn ensure_text_part(root: &mut Part) {
    if has_no_text_part(root) {
        let mut h = Header::new();
        h.set("Content-Type", "text/plain;charset=utf8");
        h.set("Content-Transfer-Encoding", "quoted-printable");
        add_child(root, Part::leaf(h, Vec::new()));
    }
}

/// Rule 9: attach an armored public key.
pub fn attach_public_key(root: &mut Part, armored: &str, identity: &str, fingerprint_hex: &str) {
    let short: String = fingerprint_hex
        .chars()
        .take(8)
        .collect::<String>()
        .to_uppercase();
    let n = q_encode_if_needed(&format!("publickey - {identity} - 0x{short}.asc"));
    let mut h = Header::new();
    h.set(
        "Content-Type",
        &format!("application/pgp-keys; name=\"{n}\"; filename=\"{n}\""),
    );
    h.set(
        "Content-Disposition",
        &format!("attachment; name=\"{n}\"; filename=\"{n}\""),
    );
    let mut p = Part::leaf(h, Vec::new());
    p.set_body(armored.as_bytes(), "base64");
    add_child(root, p);
}

fn first_address(h: &Header, name: &str, lenient: bool) -> Result<Option<Addr>> {
    match h.get(name) {
        None => Ok(None),
        Some(v) if v.trim().is_empty() => Ok(None),
        Some(v) => match parse_address_list(&v) {
            Some(l) => Ok(l.into_iter().next()),
            None if lenient => Ok(parse_address_list_lenient(&v).into_iter().next()),
            None => Err(Error::Mime(format!("invalid {name} header"))),
        },
    }
}

fn address_list(h: &Header, name: &str, lenient: bool) -> Result<Vec<Addr>> {
    let all = h.get_all(name).join(", ");
    if all.trim().is_empty() {
        return Ok(Vec::new());
    }
    match parse_address_list(&all) {
        Some(l) => Ok(l),
        None if lenient => Ok(parse_address_list_lenient(&all)),
        None => Err(Error::Mime(format!("invalid {name} header"))),
    }
}

/// Parse and normalise a message. `lenient` tolerates invalid address lists
/// (IMAP draft APPEND); SMTP submission rejects them.
pub fn parse_message(data: &[u8], lenient: bool) -> Result<ParsedMessage> {
    let data = trim_end_of_data(data);
    let mut root = Part::parse(data).ok_or_else(|| Error::Mime("invalid message header".into()))?;
    normalise_charsets(&mut root);
    inline_image_patch(&mut root);
    finish_model(root, lenient)
}

/// Extract the model from an already normalised tree (rules 5–7).
pub fn finish_model(mut root: Part, lenient: bool) -> Result<ParsedMessage> {
    let h = root.header.clone();
    let subject = h
        .get("Subject")
        .map(|s| decode_rfc2047(&s))
        .unwrap_or_default();
    let from = first_address(&h, "From", lenient)?;
    let to = address_list(&h, "To", lenient)?;
    let cc = address_list(&h, "Cc", lenient)?;
    let bcc = address_list(&h, "Bcc", lenient)?;
    let reply_to = address_list(&h, "Reply-To", lenient)?;
    let external_id = h
        .get("Message-Id")
        .map(|v| strip_angles(&v))
        .unwrap_or_default();
    let in_reply_to = h
        .get("In-Reply-To")
        .map(|v| strip_angles(&v))
        .filter(|v| !v.is_empty());
    let forward_id = h
        .get("X-Forwarded-Message-Id")
        .map(|v| strip_angles(&v))
        .filter(|v| !v.is_empty());
    let references = h
        .get_all("References")
        .join(" ")
        .split(|c: char| c.is_whitespace() || c == ',')
        .map(strip_angles)
        .filter(|s| !s.is_empty())
        .collect();

    let mut attachments = Vec::new();
    collect_attachments(&root, &mut attachments);

    let mut rich = Vec::new();
    collect_bodies(&root, true, &mut rich);
    let rich_body = rich
        .iter()
        .filter(|(t, _)| t == "text/html")
        .map(|(_, b)| b.as_str())
        .collect::<String>();
    let mut plain = Vec::new();
    collect_bodies(&root, false, &mut plain);
    let plain_body = plain
        .iter()
        .map(|(t, b)| {
            if t == "text/html" {
                mail_parser::html_to_text(b)
            } else {
                b.clone()
            }
        })
        .collect::<String>();
    let mime_type = if has_html(&root) {
        "text/html"
    } else {
        "text/plain"
    }
    .to_string();

    reencode_8bit(&mut root);
    let mime_body = root.to_bytes();

    Ok(ParsedMessage {
        root,
        subject,
        from,
        to,
        cc,
        bcc,
        reply_to,
        external_id,
        in_reply_to,
        forward_id,
        references,
        attachments,
        rich_body,
        plain_body,
        mime_type,
        mime_body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_plain() {
        let m = parse_message(
            b"From: A <a@x.org>\r\nTo: b@y.org\r\nSubject: =?utf-8?q?h=C3=A9?=\r\nMessage-ID: <id@x>\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\r\ncaf\xe9\r\n.\r\n",
            false,
        )
        .unwrap();
        assert_eq!(m.subject, "hé");
        assert_eq!(m.external_id, "id@x");
        assert_eq!(m.mime_type, "text/plain");
        assert_eq!(m.plain_body.trim_end(), "café");
        assert!(m.attachments.is_empty());
    }

    #[test]
    fn alternative_and_attachment() {
        let raw = b"From: a@x.org\r\nTo: b@y.org\r\nContent-Type: multipart/mixed; boundary=b1\r\n\r\n--b1\r\nContent-Type: multipart/alternative; boundary=b2\r\n\r\n--b2\r\nContent-Type: text/plain\r\n\r\nplain\r\n--b2\r\nContent-Type: text/html\r\n\r\n<b>rich</b>\r\n--b2--\r\n--b1\r\nContent-Type: application/pdf; name=\"x.pdf\"\r\nContent-Disposition: attachment\r\nContent-Transfer-Encoding: base64\r\n\r\naGk=\r\n--b1--\r\n";
        let m = parse_message(raw, false).unwrap();
        assert_eq!(m.mime_type, "text/html");
        assert_eq!(m.rich_body, "<b>rich</b>");
        assert_eq!(m.plain_body, "plain");
        assert_eq!(m.attachments.len(), 1);
        assert_eq!(m.attachments[0].name, "x.pdf");
        assert_eq!(m.attachments[0].data, b"hi");
        assert_eq!(m.attachments[0].mime_type, "application/pdf");
    }

    #[test]
    fn invalid_addresses() {
        let raw = b"From: a@x.org\r\nTo: not valid\r\n\r\nbody";
        assert!(parse_message(raw, false).is_err());
        assert!(parse_message(raw, true).is_ok());
    }

    #[test]
    fn empty_text_part() {
        let mut p = Part::parse(b"Content-Type: application/pdf\r\n\r\nxx").unwrap();
        assert!(has_no_text_part(&p));
        ensure_text_part(&mut p);
        assert_eq!(p.content_type().value, "multipart/mixed");
        assert_eq!(p.children.len(), 2);
        assert!(!has_no_text_part(&p) || p.children[1].header.get("Content-Disposition").is_none());
    }

    #[test]
    fn meta_rewrite() {
        let h = "<html><head><meta charset=\"iso-8859-1\"></head></html>";
        assert_eq!(
            rewrite_meta_charset(h).unwrap(),
            "<html><head><meta charset=\"UTF-8\"></head></html>"
        );
        assert!(rewrite_meta_charset("<meta charset=utf-8>").is_none());
    }
}
