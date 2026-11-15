//! Literal synthesis (§11.8): rebuild a standard RFC 5322 / MIME message from
//! a Service message and its decrypted parts.

use crate::api::types::{Attachment, Message, MessageMetadata};
use crate::config::LocalArtifacts;
use crate::crypto::{self, KeyRing};
use crate::error::{Error, Result};
use crate::mime::{
    ContentType, Header, HeaderField, Part, decode_rfc2047, format_address, format_address_list,
    parse_address_list, parse_date, q_encode, q_encode_if_needed, qp_encode, split_entity,
};
use crate::util::{b64_decode, b64_wrapped, mime_boundary, rfc1123z_ts};

/// Unix time of 1982-08-13 00:00:00 +0000 (fallback date).
const FALLBACK_DATE: i64 = 397_958_400;
/// Representation of a zero (unknown) original date.
const ZERO_DATE: &str = "Mon, 01 Jan 0001 00:00:00 +0000";

/// The decrypted body (or the reason it could not be decrypted).
pub type BodyResult = std::result::Result<crypto::Decrypted, String>;

/// One attachment with its downloaded data packet and decryption outcome.
#[derive(Debug, Clone)]
pub struct AttachmentData {
    pub attachment: Attachment,
    pub data_packet: Vec<u8>,
    pub decrypted: std::result::Result<Vec<u8>, String>,
}

/// Decrypt a message body and its attachments with an Address key ring
/// (§9.2). Failures are recorded per item.
pub fn decrypt_message(
    msg: &Message,
    ring: &KeyRing,
    data_packets: Vec<Vec<u8>>,
) -> (BodyResult, Vec<AttachmentData>) {
    let body = ring.decrypt(msg.body.as_bytes()).map_err(|e| e.to_string());
    let atts = msg
        .attachments
        .iter()
        .cloned()
        .zip(data_packets)
        .map(|(attachment, data_packet)| {
            let decrypted = b64_decode(&attachment.key_packets)
                .and_then(|mut kp| {
                    kp.extend_from_slice(&data_packet);
                    ring.decrypt(&kp).map(|d| d.data)
                })
                .map_err(|e| e.to_string());
            AttachmentData {
                attachment,
                data_packet,
                decrypted,
            }
        })
        .collect();
    (body, atts)
}

/// Build the literal; on total failure return the build-failure
/// placeholder (§11.8.5). The boolean is true if the message must be
/// recorded as failed.
pub fn build_or_placeholder(
    msg: &Message,
    body: BodyResult,
    atts: Vec<AttachmentData>,
    art: &LocalArtifacts,
) -> (Vec<u8>, bool) {
    match build_literal(msg, body, atts, art) {
        Ok(l) => (l, false),
        Err(e) => (
            build_failure_placeholder(&msg.metadata, &e.to_string()),
            true,
        ),
    }
}

/// Build the literal for a message (§11.8).
pub fn build_literal(
    msg: &Message,
    body: BodyResult,
    atts: Vec<AttachmentData>,
    art: &LocalArtifacts,
) -> Result<Vec<u8>> {
    let mut top = synthesize_header(msg, art);
    let body = body.map(|mut d| {
        d.data = strip_mbox_lines(&d.data);
        d
    });

    let has_attachments = !atts.is_empty();
    let is_pgp_mime = msg.mime_type.eq_ignore_ascii_case("multipart/mixed");

    if !has_attachments && is_pgp_mime {
        return Ok(match body {
            Ok(d) => build_pgp_mime(top, d)?,
            Err(reason) => build_pgp_mime_failure(top, msg, &reason)?,
        });
    }

    let text_part = match &body {
        Ok(d) => text_part(&msg.mime_type, &d.data),
        Err(reason) => failed_body_part(msg, reason)?,
    };

    if !has_attachments && body.is_ok() {
        // Case C — single part.
        for f in text_part.header.fields {
            top.set(&f.name, &f.value());
        }
        let mut out = top.to_bytes();
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&text_part.body);
        return Ok(out);
    }

    // Case A — multipart/mixed (also used for body failures in A and C).
    let (inline, regular): (Vec<_>, Vec<_>) = atts
        .into_iter()
        .partition(|a| a.attachment.disposition.eq_ignore_ascii_case("inline"));
    let first = if inline.is_empty() {
        text_part
    } else {
        let mut kids = vec![text_part];
        for a in &inline {
            kids.push(attachment_part(a)?);
        }
        Part::multipart("related", mime_boundary(), kids)
    };
    let mut children = vec![first];
    for a in &regular {
        children.push(attachment_part(a)?);
    }
    let b1 = mime_boundary();
    top.set("Content-Type", &format!("multipart/mixed; boundary={b1}"));
    top.remove("Content-Transfer-Encoding");
    let root = Part {
        header: top,
        children,
        boundary: Some(b1),
        ..Default::default()
    };
    Ok(root.to_bytes())
}

fn set_if_differs(h: &mut Header, name: &str, value: &str) {
    if h.get(name).as_deref() != Some(value) {
        h.set(name, value);
    }
}

fn same_addresses(existing: Option<String>, want: &[crate::api::types::Addr]) -> bool {
    let Some(e) = existing else { return false };
    let Some(list) = parse_address_list(&e) else {
        return false;
    };
    list.len() == want.len()
        && list
            .iter()
            .zip(want)
            .all(|(a, b)| a.address.eq_ignore_ascii_case(&b.address) && a.name == b.name)
}

/// Top-level header synthesis (§11.8.2).
pub fn synthesize_header(msg: &Message, art: &LocalArtifacts) -> Header {
    let m = &msg.metadata;
    let mut h = Header::new();
    for (k, v) in msg.parsed_headers.fields() {
        h.add_raw(HeaderField::new(k, v));
    }

    if !m.subject.is_empty() {
        let same = h
            .get("Subject")
            .map(|s| decode_rfc2047(&s) == m.subject)
            .unwrap_or(false);
        if !same {
            h.set("Subject", &q_encode_if_needed(&m.subject));
        }
    }
    if !m.sender.is_empty() && !same_addresses(h.get("From"), std::slice::from_ref(&m.sender)) {
        h.set("From", &format_address(&m.sender));
    }
    let single_empty_reply_to = m.reply_tos.len() == 1 && m.reply_tos[0].is_empty();
    if !m.is_draft()
        && !single_empty_reply_to
        && !m.reply_tos.is_empty()
        && !same_addresses(h.get("Reply-To"), &m.reply_tos)
    {
        h.set("Reply-To", &format_address_list(&m.reply_tos));
    }
    for (name, list) in [("To", &m.to_list), ("Cc", &m.cc_list), ("Bcc", &m.bcc_list)] {
        if !list.is_empty() && !same_addresses(h.get(name), list) {
            h.set(name, &format_address_list(list));
        }
    }
    if !h.contains("Message-Id") {
        let id = if !m.external_id.is_empty() {
            format!("<{}>", m.external_id)
        } else {
            format!("<{}@{}>", m.id, art.internal_id_domain)
        };
        h.set("Message-Id", &id);
    }

    let time_str = rfc1123z_ts(if m.time > 0 { m.time } else { FALLBACK_DATE });
    let parsed = h.get("Date").and_then(|d| parse_date(&d));
    let date_ok = parsed.map(|d| d.timestamp() >= 0).unwrap_or(false);
    if !date_ok {
        h.set("Date", &time_str);
        if !h.contains("X-Original-Date") {
            let orig = parsed
                .map(crate::util::rfc1123z)
                .unwrap_or_else(|| ZERO_DATE.to_string());
            h.set("X-Original-Date", &orig);
        }
    }

    set_if_differs(&mut h, &art.hdr_internal_id, &m.id);
    if !m.external_id.is_empty() {
        set_if_differs(
            &mut h,
            &art.hdr_external_id,
            &format!("<{}>", m.external_id),
        );
    }
    set_if_differs(&mut h, &art.hdr_server_date, &rfc1123z_ts(m.time.max(0)));

    let refs = h.get_all("References");
    if !refs.iter().any(|r| r.contains(&m.id)) {
        let own = format!("<{}@{}>", m.id, art.internal_id_domain);
        let joined = refs.join(" ");
        let v = if joined.trim().is_empty() {
            own
        } else {
            format!("{} {own}", joined.trim())
        };
        h.set("References", &v);
    }
    h
}

/// Remove mbox `From ` delimiter lines from a leading header section that
/// contains From:, To: and Date: (§11.8.1).
fn strip_mbox_lines(data: &[u8]) -> Vec<u8> {
    let end = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .or_else(|| data.windows(2).position(|w| w == b"\n\n"));
    let Some(end) = end else {
        return data.to_vec();
    };
    let section = &data[..end];
    let lower = String::from_utf8_lossy(section).to_ascii_lowercase();
    let has = |f: &str| lower.starts_with(f) || lower.contains(&format!("\n{f}"));
    if !(has("from:") && has("to:") && has("date:")) {
        return data.to_vec();
    }
    let mut out = Vec::with_capacity(data.len());
    for line in section.split_inclusive(|&b| b == b'\n') {
        if line.starts_with(b"From ") || line.starts_with(b">From ") {
            continue;
        }
        out.extend_from_slice(line);
    }
    out.extend_from_slice(&data[end..]);
    out
}

fn text_part(mime_type: &str, body: &[u8]) -> Part {
    let mime = if mime_type.is_empty() {
        "text/plain"
    } else {
        mime_type
    };
    let mut h = Header::new();
    if std::str::from_utf8(body).is_ok() {
        h.set("Content-Type", &format!("{mime}; charset=utf-8"));
    } else {
        h.set("Content-Type", mime);
    }
    h.set("Content-Transfer-Encoding", "quoted-printable");
    Part::leaf(h, qp_encode(body).into_bytes())
}

fn rearmor(armored: &str, comment: &str) -> String {
    match crypto::dearmor(armored.as_bytes())
        .and_then(|bin| crypto::armor_message(&bin, Some(comment)))
    {
        Ok(a) => a,
        Err(_) => armored.to_string(),
    }
}

fn failed_body_part(msg: &Message, reason: &str) -> Result<Part> {
    let comment = format!("This message could not be decrypted: {reason}");
    let mut h = Header::new();
    h.set(
        "Content-Type",
        if msg.mime_type.is_empty() {
            "text/plain"
        } else {
            &msg.mime_type
        },
    );
    Ok(Part::leaf(
        h,
        crate::mime::normalize_crlf(rearmor(&msg.body, &comment).as_bytes()),
    ))
}

fn attachment_part(a: &AttachmentData) -> Result<Part> {
    let att = &a.attachment;
    let mut h = Header::new();
    for (k, v) in att.headers.fields() {
        h.add_raw(HeaderField::new(k, v));
    }
    let disposition = if att.disposition.is_empty() {
        "attachment"
    } else {
        att.disposition.as_str()
    };
    match &a.decrypted {
        Ok(data) => {
            let qname = q_encode_if_needed(&att.name);
            match ContentType::parse(&att.mime_type) {
                Some(mut ct) => {
                    ct.set_param("name", &qname);
                    ct.set_param("filename", &qname);
                    h.set("Content-Type", &ct.to_string());
                }
                None => h.set("Content-Type", &att.mime_type),
            }
            let mut cd = ContentType::new(disposition);
            cd.set_param("filename", &qname);
            h.set("Content-Disposition", &cd.to_string());
            if att
                .mime_type
                .to_ascii_lowercase()
                .starts_with("message/rfc822")
            {
                h.remove("Content-Transfer-Encoding");
                Ok(Part::leaf(h, data.clone()))
            } else {
                h.set("Content-Transfer-Encoding", "base64");
                Ok(Part::leaf(h, b64_wrapped(data).into_bytes()))
            }
        }
        Err(reason) => {
            let pgp_name = format!("{}.pgp", att.name);
            let qname = if pgp_name.is_ascii() {
                pgp_name
            } else {
                q_encode(&pgp_name)
            };
            h.set(
                "Content-Type",
                &format!("application/octet-stream; name=\"{qname}\""),
            );
            h.set(
                "Content-Disposition",
                &format!("{disposition}; filename=\"{qname}\""),
            );
            h.remove("Content-Transfer-Encoding");
            let mut bin = b64_decode(&att.key_packets).unwrap_or_default();
            bin.extend_from_slice(&a.data_packet);
            let comment = format!("This attachment could not be decrypted: {reason}");
            let armored = crypto::armor_message(&bin, Some(&comment))?;
            Ok(Part::leaf(
                h,
                crate::mime::normalize_crlf(armored.as_bytes()),
            ))
        }
    }
}

/// Case B — PGP/MIME reconstruction.
fn build_pgp_mime(mut top: Header, d: crypto::Decrypted) -> Result<Vec<u8>> {
    if let Some((sig, hash)) = d.signature {
        let b = mime_boundary();
        top.set(
            "Content-Type",
            &format!(
                "multipart/signed; micalg={hash}; protocol=\"application/pgp-signature\"; boundary={b}"
            ),
        );
        top.remove("Content-Transfer-Encoding");
        let armored_sig = crypto::armor_signature(&sig)?;
        let mut out = top.to_bytes();
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(format!("--{b}\r\n").as_bytes());
        out.extend_from_slice(&d.data);
        out.extend_from_slice(format!("\r\n--{b}\r\n").as_bytes());
        out.extend_from_slice(
            b"Content-Type: application/pgp-signature; name=\"OpenPGP_signature.asc\"\r\n\
Content-Disposition: attachment; filename=\"OpenPGP_signature\"\r\n\
Content-Description: OpenPGP digital signature\r\n\r\n",
        );
        out.extend_from_slice(&crate::mime::normalize_crlf(armored_sig.as_bytes()));
        out.extend_from_slice(format!("\r\n--{b}--\r\n").as_bytes());
        return Ok(out);
    }
    top.remove("Content-Type");
    let body = match split_entity(&d.data) {
        Some((eh, body)) => {
            for f in eh.fields {
                if !top.contains(&f.name) {
                    top.add_raw(f);
                }
            }
            body
        }
        None => d.data,
    };
    let mut out = top.to_bytes();
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&body);
    Ok(out)
}

fn build_pgp_mime_failure(mut top: Header, msg: &Message, _reason: &str) -> Result<Vec<u8>> {
    let b = mime_boundary();
    top.set(
        "Content-Type",
        &format!("multipart/encrypted; boundary={b}; protocol=\"application/pgp-encrypted\""),
    );
    top.remove("Content-Transfer-Encoding");
    let mut out = top.to_bytes();
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(
        format!(
            "--{b}\r\nContent-Type: application/pgp-encrypted\r\n\
Content-Description: PGP/MIME version identification\r\n\r\nVersion: 1\r\n\
--{b}\r\nContent-Type: application/octet-stream; name=\"encrypted.asc\"\r\n\
Content-Disposition: inline; filename=\"encrypted.asc\"\r\n\
Content-Description: OpenPGP encrypted message\r\n\r\n"
        )
        .as_bytes(),
    );
    out.extend_from_slice(&crate::mime::normalize_crlf(msg.body.as_bytes()));
    out.extend_from_slice(format!("\r\n--{b}--\r\n").as_bytes());
    Ok(out)
}

/// The build-failure placeholder literal (§11.8.5).
pub fn build_failure_placeholder(m: &MessageMetadata, error: &str) -> Vec<u8> {
    let text = format!(
        "Failed to build message: \nSubject:   {}\nError:     {}\nMessageID: {}\n",
        m.subject, error, m.id
    );
    let mut out = format!(
        "Date: {}\r\nSubject: Message failed to build\r\nContent-Type: text/plain\r\n\
Content-Transfer-Encoding: base64\r\n\r\n",
        rfc1123z_ts(m.time)
    )
    .into_bytes();
    out.extend_from_slice(b64_wrapped(text.as_bytes()).as_bytes());
    out
}

/// Convenience: decrypt and build in one step.
pub fn decrypt_and_build(
    msg: &Message,
    ring: &KeyRing,
    data_packets: Vec<Vec<u8>>,
    art: &LocalArtifacts,
) -> (Vec<u8>, bool) {
    if data_packets.len() != msg.attachments.len() {
        let e = Error::Invalid("attachment data count mismatch".into());
        return (
            build_failure_placeholder(&msg.metadata, &e.to_string()),
            true,
        );
    }
    let (body, atts) = decrypt_message(msg, ring, data_packets);
    build_or_placeholder(msg, body, atts, art)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::{Addr, ParsedHeaders};

    fn sample() -> Message {
        let mut m = Message::default();
        m.metadata.id = "abc".into();
        m.metadata.subject = "Hällo".into();
        m.metadata.sender = Addr::new("Ann", "ann@example.org");
        m.metadata.to_list = vec![Addr::new("", "bob@example.org")];
        m.metadata.time = 1_700_000_000;
        m.metadata.flags = 1;
        m.mime_type = "text/plain".into();
        m.parsed_headers = ParsedHeaders(vec![
            ("Received".into(), vec!["a".into(), "b".into()]),
            ("Date".into(), vec!["garbage".into()]),
        ]);
        m
    }

    #[test]
    fn single_part() {
        let m = sample();
        let d = crypto::Decrypted {
            data: b"hello".to_vec(),
            signature: None,
        };
        let lit = build_literal(&m, Ok(d), vec![], &LocalArtifacts::default()).unwrap();
        let s = String::from_utf8(lit).unwrap();
        assert!(s.starts_with("Received: a\r\nReceived: b\r\nDate: Tue, 14 Nov 2023"));
        assert!(s.contains("X-Original-Date: Mon, 01 Jan 0001 00:00:00 +0000\r\n"));
        assert!(s.contains("Subject: =?UTF-8?Q?H=C3=A4llo?=\r\n"));
        assert!(s.contains("Message-Id: <abc@internal.invalid>\r\n"));
        assert!(s.contains("References: <abc@internal.invalid>\r\n"));
        assert!(s.contains("Content-Type: text/plain; charset=utf-8\r\n"));
        assert!(s.ends_with("\r\n\r\nhello"));
    }

    #[test]
    fn with_attachment() {
        let m = sample();
        let d = crypto::Decrypted {
            data: b"hello".to_vec(),
            signature: None,
        };
        let att = AttachmentData {
            attachment: Attachment {
                id: "a1".into(),
                name: "f.txt".into(),
                mime_type: "text/plain".into(),
                disposition: "attachment".into(),
                ..Default::default()
            },
            data_packet: vec![],
            decrypted: Ok(b"data".to_vec()),
        };
        let lit = build_literal(&m, Ok(d), vec![att], &LocalArtifacts::default()).unwrap();
        let p = Part::parse(&lit).unwrap();
        assert_eq!(p.content_type().value, "multipart/mixed");
        assert_eq!(p.children.len(), 2);
        assert_eq!(p.children[1].decoded_body(), b"data");
    }

    #[test]
    fn placeholder() {
        let m = sample();
        let p = build_failure_placeholder(&m.metadata, "boom");
        let part = Part::parse(&p).unwrap();
        let txt = String::from_utf8(part.decoded_body()).unwrap();
        assert!(txt.contains("Error:     boom"));
    }
}
