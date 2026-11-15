//! Package construction for send (§13.13, §9.7).

use std::collections::BTreeMap;

use tracing::warn;

use super::prefs::{SendPreferences, scheme, signature_type};
use crate::api::mail::{PackageAddress, SendPackage, SessionKeyJson};
use crate::crypto::{self, KeyRing, SessionKey};
use crate::error::{Error, Result};
use crate::util::b64;

fn sk_json(sk: &SessionKey) -> SessionKeyJson {
    SessionKeyJson {
        key: sk.key_b64(),
        algorithm: sk.algorithm_name().to_string(),
    }
}

/// Encrypt a package body to the first key, signed (§9.7 steps 1–3).
fn encrypt_body(ring: &KeyRing, body: &[u8]) -> Result<(String, SessionKey)> {
    let (bin, session) = ring.encrypt(body, true, "")?;
    let (_key_packets, data) = crypto::split_message(&bin)?;
    Ok((b64(data), session))
}

/// Build the send packages.
pub fn build_packages(
    ring: &KeyRing,
    recipients: &[(String, SendPreferences)],
    rich_body: &str,
    plain_body: &str,
    mime_body: &[u8],
    attachment_keys: &BTreeMap<String, SessionKey>,
) -> Result<Vec<SendPackage>> {
    let mut packages = Vec::new();

    // MIME package.
    let mime_recips: Vec<&(String, SendPreferences)> = recipients
        .iter()
        .filter(|(_, p)| p.scheme == scheme::PGP_MIME || p.scheme == scheme::CLEAR_MIME)
        .collect();
    if !mime_recips.is_empty() {
        let (body, sk) = encrypt_body(ring, mime_body)?;
        let mut pkg = SendPackage {
            mime_type: "multipart/mixed".into(),
            body,
            ..Default::default()
        };
        for (email, p) in mime_recips {
            if p.mime_type != "multipart/mixed" || p.signature_type != signature_type::DETACHED {
                return Err(Error::Invalid(format!(
                    "invalid MIME package preferences for {email}"
                )));
            }
            let mut addr = PackageAddress {
                scheme: p.scheme,
                signature: p.signature_type,
                ..Default::default()
            };
            if p.scheme == scheme::PGP_MIME {
                let k = p
                    .pub_key
                    .as_ref()
                    .ok_or_else(|| Error::Invalid(format!("no public key for {email}")))?;
                addr.body_key_packet = Some(b64(sk.encrypt_to(k)?));
            } else {
                pkg.body_key = Some(sk_json(&sk));
            }
            pkg.scheme |= p.scheme;
            pkg.addresses.insert(email.clone(), addr);
        }
        packages.push(pkg);
    }

    // Text packages, grouped by MIME type.
    let mut groups: BTreeMap<String, Vec<&(String, SendPreferences)>> = BTreeMap::new();
    for r in recipients.iter().filter(|(_, p)| {
        matches!(
            p.scheme,
            scheme::INTERNAL | scheme::CLEAR | scheme::PGP_INLINE
        )
    }) {
        groups.entry(r.1.mime_type.clone()).or_default().push(r);
    }
    for (mime, recips) in groups {
        let body = match mime.as_str() {
            "text/html" => rich_body,
            "text/plain" => plain_body,
            other => {
                return Err(Error::Invalid(format!(
                    "text package cannot have MIME type {other}"
                )));
            }
        };
        let (enc_body, sk) = encrypt_body(ring, body.as_bytes())?;
        let mut pkg = SendPackage {
            mime_type: mime.clone(),
            body: enc_body,
            ..Default::default()
        };
        for (email, p) in recips {
            if p.scheme == scheme::INTERNAL && !p.encrypt {
                return Err(Error::Invalid(format!(
                    "internal recipient {email} must be encrypted"
                )));
            }
            if p.scheme == scheme::PGP_INLINE && mime != "text/plain" {
                return Err(Error::Invalid(format!(
                    "PGP/Inline for {email} requires text/plain"
                )));
            }
            if p.sign && !p.encrypt {
                if p.scheme == scheme::PGP_INLINE {
                    return Err(Error::Invalid(format!("invalid scheme for {email}")));
                }
                if p.scheme == scheme::CLEAR && mime != "text/plain" {
                    return Err(Error::Invalid(format!(
                        "signed clear message to {email} requires text/plain"
                    )));
                }
            }
            if p.scheme == scheme::PGP_INLINE {
                warn!("PGP/Inline is deprecated (recipient {email})");
            }
            let mut addr = PackageAddress {
                scheme: p.scheme,
                signature: p.signature_type,
                ..Default::default()
            };
            if p.scheme == scheme::CLEAR {
                pkg.body_key = Some(sk_json(&sk));
                for (id, ak) in attachment_keys {
                    pkg.attachment_keys.insert(id.clone(), sk_json(ak));
                }
            }
            if p.encrypt {
                let k = p
                    .pub_key
                    .as_ref()
                    .ok_or_else(|| Error::Invalid(format!("no public key for {email}")))?;
                if p.signature_type != signature_type::DETACHED {
                    return Err(Error::Invalid(format!(
                        "encrypted recipient {email} must be signed"
                    )));
                }
                addr.body_key_packet = Some(b64(sk.encrypt_to(k)?));
                for (id, ak) in attachment_keys {
                    addr.attachment_key_packets
                        .insert(id.clone(), b64(ak.encrypt_to(k)?));
                }
            }
            pkg.scheme |= p.scheme;
            pkg.addresses.insert(email.clone(), addr);
        }
        packages.push(pkg);
    }
    Ok(packages)
}
