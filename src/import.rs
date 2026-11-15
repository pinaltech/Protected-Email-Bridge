//! Import encryption (§9.6): encrypt a literal to an Address's first key
//! before `POST /mail/v4/messages/import`.

use crate::crypto::KeyRing;
use crate::error::{Error, Result};
use crate::mime::{ContentType, Part, decode_charset};
use crate::util::{b64_wrapped, random_hex};

/// Encrypt a literal for import, preferring per-part mode and falling back
/// to full PGP/MIME mode.
pub fn encrypt_for_import(literal: &[u8], ring: &KeyRing) -> Result<Vec<u8>> {
    if let Some(root) = Part::parse(literal)
        && per_part_eligible(&root)
        && let Ok(out) = encrypt_per_part(root, ring)
    {
        return Ok(out);
    }
    encrypt_full(literal, ring)
}

fn per_part_eligible(root: &Part) -> bool {
    let mut text_parts = 0;
    let mut ok = true;
    let mut stack = vec![root];
    while let Some(p) = stack.pop() {
        if p.header.fields.is_empty() && !p.body.is_empty() && !std::ptr::eq(p, root) {
            // A child whose header could not be parsed.
            ok = false;
        }
        if p.header.get("Content-Type").is_some() && p.header.content_type().is_none() {
            ok = false;
        }
        if p.header.get("Content-Disposition").is_some() && p.disposition().is_none() {
            ok = false;
        }
        let ct = p.content_type();
        if matches!(ct.sub_type(), "encrypted" | "signed") {
            ok = false;
        }
        if !p.is_multipart() && ct.main_type() == "text" {
            text_parts += 1;
            if text_parts > 1 {
                ok = false;
            }
        }
        stack.extend(p.children.iter());
    }
    ok
}

fn encrypt_per_part(mut root: Part, ring: &KeyRing) -> Result<Vec<u8>> {
    let mut failure: Option<Error> = None;
    root.visit_mut(&mut |p: &mut Part| {
        if p.is_multipart() || failure.is_some() {
            return;
        }
        let ct = p.content_type();
        let decoded = p.decoded_body();
        if matches!(ct.main_type(), "text" | "message") {
            let text = match ct.param("charset") {
                Some(cs) => match decode_charset(&decoded, cs) {
                    Some(t) => {
                        let mut nct: ContentType = ct.clone();
                        nct.set_param("charset", "utf-8");
                        p.header.set("Content-Type", &nct.to_string());
                        t.into_bytes()
                    }
                    None => {
                        failure = Some(Error::Mime(format!("unknown charset {cs}")));
                        return;
                    }
                },
                None => decoded,
            };
            p.header.remove("Content-Transfer-Encoding");
            match ring.encrypt_armored(&text, false) {
                Ok(a) => p.body = crate::mime::normalize_crlf(a.as_bytes()),
                Err(e) => failure = Some(e),
            }
        } else {
            match ring.encrypt(&decoded, false, "") {
                Ok((bin, _)) => {
                    p.header.set("Content-Transfer-Encoding", "base64");
                    p.body = b64_wrapped(&bin).into_bytes();
                }
                Err(e) => failure = Some(e),
            }
        }
    });
    match failure {
        Some(e) => Err(e),
        None => Ok(root.to_bytes()),
    }
}

fn encrypt_full(literal: &[u8], ring: &KeyRing) -> Result<Vec<u8>> {
    let armored = ring.encrypt_armored(literal, true)?;
    let mut out = Vec::new();
    if let Some(root) = Part::parse(literal) {
        for name in [
            "Message-Id",
            "From",
            "To",
            "Subject",
            "Date",
            "Received",
            "Cc",
        ] {
            for f in root
                .header
                .fields
                .iter()
                .filter(|f| f.name.eq_ignore_ascii_case(name))
            {
                out.extend_from_slice(&crate::mime::normalize_crlf(&f.raw));
                out.extend_from_slice(b"\r\n");
            }
        }
    }
    let b = random_hex(16);
    out.extend_from_slice(
        format!(
            "Mime-version: 1.0\r\nContent-Type: multipart/encrypted; boundary={b}; protocol=\"application/pgp-encrypted\"\r\n\r\n\
--{b}\r\nContent-Description: PGP/MIME version identification\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n\
--{b}\r\nContent-Description: OpenPGP encrypted message\r\nContent-Disposition: inline; filename=encrypted.asc\r\n\
Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\n\r\n"
        )
        .as_bytes(),
    );
    out.extend_from_slice(&crate::mime::normalize_crlf(armored.as_bytes()));
    out.extend_from_slice(format!("\r\n--{b}--\r\n").as_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eligibility() {
        let one = Part::parse(b"Content-Type: text/plain\r\n\r\nhi").unwrap();
        assert!(per_part_eligible(&one));
        let two = Part::parse(b"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\na\r\n--x\r\nContent-Type: text/html\r\n\r\nb\r\n--x--\r\n").unwrap();
        assert!(!per_part_eligible(&two));
        let signed = Part::parse(b"Content-Type: multipart/signed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\na\r\n--x--\r\n").unwrap();
        assert!(!per_part_eligible(&signed));
    }
}
