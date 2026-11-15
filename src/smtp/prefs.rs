//! Per-recipient send preference resolution (§13.12) and contact card
//! processing (§7.6, §9.8).

use pgp::composed::SignedPublicKey;

use crate::api::types::{Card, MailSettings, PublicKeys, card_type, recipient_type};
use crate::crypto::{self, KeyRing};
use crate::error::{Error, Result};
use crate::gateway::AccountContext;
use crate::util::b64_decode;

/// Encryption scheme values.
pub mod scheme {
    pub const INTERNAL: i64 = 1;
    pub const ENCRYPTED_OUTSIDE: i64 = 2;
    pub const CLEAR: i64 = 4;
    pub const PGP_INLINE: i64 = 8;
    pub const PGP_MIME: i64 = 16;
    pub const CLEAR_MIME: i64 = 32;
}

/// Signature type values.
pub mod signature_type {
    pub const NONE: i64 = 0;
    pub const DETACHED: i64 = 1;
    pub const ATTACHED: i64 = 2;
}

/// Preferences read from the signed contact card group.
#[derive(Debug, Clone)]
pub struct ContactSettings {
    pub mime_type: Option<String>,
    pub scheme: Option<String>,
    pub sign: Option<bool>,
    pub encrypt: Option<bool>,
    pub encrypt_untrusted: bool,
    pub keys: Vec<SignedPublicKey>,
}

impl Default for ContactSettings {
    fn default() -> Self {
        Self {
            mime_type: None,
            scheme: None,
            sign: None,
            encrypt: None,
            encrypt_untrusted: true,
            keys: Vec::new(),
        }
    }
}

/// Unfold vCard content lines.
fn vcard_lines(vcard: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in vcard.split('\n') {
        let line = raw.trim_end_matches('\r');
        if (line.starts_with(' ') || line.starts_with('\t')) && !out.is_empty() {
            out.last_mut().expect("non-empty").push_str(&line[1..]);
        } else if !line.is_empty() {
            out.push(line.to_string());
        }
    }
    out
}

/// Split `group.NAME;params:value` into (group, NAME, value).
fn vcard_prop(line: &str) -> Option<(Option<String>, String, String)> {
    let (left, value) = line.split_once(':')?;
    let name_part = left.split(';').next().unwrap_or(left);
    let (group, name) = match name_part.split_once('.') {
        Some((g, n)) => (Some(g.to_string()), n.to_string()),
        None => (None, name_part.to_string()),
    };
    Some((group, name.to_ascii_uppercase(), value.to_string()))
}

fn parse_bool(v: &str) -> Option<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// Read the preferences of the group whose EMAIL equals `email`.
pub fn parse_vcard_settings(vcard: &str, email: &str) -> Option<ContactSettings> {
    let props: Vec<_> = vcard_lines(vcard)
        .iter()
        .filter_map(|l| vcard_prop(l))
        .collect();
    let group = props.iter().find_map(|(g, n, v)| {
        (n == "EMAIL" && v.trim().eq_ignore_ascii_case(email.trim()))
            .then(|| g.clone())
            .flatten()
    })?;
    let mut s = ContactSettings::default();
    for (g, n, v) in props
        .iter()
        .filter(|(g, _, _)| g.as_deref() == Some(&group))
    {
        let _ = g;
        match n.as_str() {
            "X-PM-SCHEME" => s.scheme = Some(v.trim().to_ascii_lowercase()),
            "X-PM-MIMETYPE" => s.mime_type = Some(v.trim().to_ascii_lowercase()),
            "X-PM-SIGN" => s.sign = parse_bool(v),
            "X-PM-ENCRYPT" => s.encrypt = parse_bool(v),
            "X-PM-ENCRYPT-UNTRUSTED" => s.encrypt_untrusted = parse_bool(v).unwrap_or(true),
            "KEY" => {
                if let Some((_, b64)) = v.split_once(',')
                    && let Ok(bin) = b64_decode(b64.trim())
                    && let Ok(k) = crypto::parse_public_key(&bin)
                {
                    s.keys.push(k);
                }
            }
            _ => {}
        }
    }
    Some(s)
}

/// Settings from a contact's cards: only the verified signed card counts.
pub fn contact_settings_from_cards(
    cards: &[Card],
    user_ring: &KeyRing,
    email: &str,
) -> ContactSettings {
    for c in cards.iter().filter(|c| c.kind == card_type::SIGNED) {
        if user_ring
            .verify_detached(c.data.as_bytes(), c.signature.as_bytes())
            .is_ok()
            && let Some(s) = parse_vcard_settings(&c.data, email)
        {
            return s;
        }
    }
    ContactSettings::default()
}

/// Resolved preferences for one recipient.
#[derive(Debug, Clone)]
pub struct SendPreferences {
    pub encrypt: bool,
    pub sign: bool,
    pub scheme: i64,
    pub signature_type: i64,
    pub mime_type: String,
    pub pub_key: Option<SignedPublicKey>,
    pub internal: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Internal,
    PgpMime,
    PgpInline,
}

fn scheme_from_str(s: &str) -> Option<Scheme> {
    match s {
        "pgp-mime" => Some(Scheme::PgpMime),
        "pgp-inline" => Some(Scheme::PgpInline),
        _ => None,
    }
}

fn select_key(service: &[SignedPublicKey], pinned: &[SignedPublicKey]) -> Option<SignedPublicKey> {
    let pinned_fps: Vec<String> = pinned.iter().map(crypto::fingerprint_hex).collect();
    service
        .iter()
        .find(|k| pinned_fps.contains(&crypto::fingerprint_hex(k)))
        .or_else(|| service.first())
        .cloned()
}

/// Compute preferences (§13.12 phases A–D).
pub fn compute(
    keys: &PublicKeys,
    contact: &ContactSettings,
    settings: &MailSettings,
    composer_mime: &str,
) -> Result<SendPreferences> {
    let service_keys: Vec<SignedPublicKey> = keys
        .keys
        .iter()
        .filter_map(|k| crypto::parse_public_key(k.public_key.as_bytes()).ok())
        .collect();
    let internal = keys.recipient_type == recipient_type::INTERNAL;

    let e: Option<bool>;
    let mut s: Option<bool> = None;
    let mut sigma: Option<Scheme> = None;
    let mut m: Option<String> = None;
    let mut k: Option<SignedPublicKey> = None;

    // Phase A.
    if internal {
        if service_keys.is_empty() {
            return Err(Error::Other("internal recipient has no keys".into()));
        }
        e = Some(true);
        s = Some(true);
        sigma = Some(Scheme::Internal);
        if let Some(mt) = &contact.mime_type {
            m = Some(mt.clone());
        }
        k = select_key(&service_keys, &contact.keys);
    } else if !service_keys.is_empty() {
        e = Some(contact.encrypt_untrusted);
        if contact.encrypt_untrusted {
            s = Some(true);
        } else if let Some(cs) = contact.sign {
            s = Some(cs);
        }
        if let Some(sc) = contact.scheme.as_deref().and_then(scheme_from_str) {
            sigma = Some(sc);
        }
        match sigma {
            Some(Scheme::PgpMime) => m = None,
            Some(Scheme::PgpInline) => m = Some("text/plain".into()),
            _ => {}
        }
        k = select_key(&service_keys, &contact.keys);
    } else {
        e = Some(contact.encrypt.unwrap_or(false));
        if let Some(cs) = contact.sign {
            s = Some(cs);
        }
        if e == Some(true) {
            s = Some(true);
        }
        if let Some(sc) = contact.scheme.as_deref().and_then(scheme_from_str) {
            sigma = Some(sc);
        }
        if contact.sign == Some(true) {
            match sigma {
                Some(Scheme::PgpMime) => m = None,
                Some(Scheme::PgpInline) => m = Some("text/plain".into()),
                _ => {}
            }
        } else if let Some(mt) = &contact.mime_type {
            m = Some(mt.clone());
        }
        if let Some(first) = contact.keys.first() {
            k = Some(first.clone());
        }
    }

    // Phase B.
    let e = e.unwrap_or(false);
    if settings.sign > 0 && s.is_none() {
        s = Some(true);
    }
    if e {
        s = Some(true);
    }
    let sign = s.unwrap_or(false);
    if sigma.is_none() {
        sigma = match settings.pgp_scheme {
            8 => Some(Scheme::PgpInline),
            16 => Some(Scheme::PgpMime),
            _ => None,
        };
    }
    if sign && sigma == Some(Scheme::PgpInline) {
        m = Some("text/plain".into());
    } else if m.is_none() {
        m = Some(settings.draft_mime_type.clone());
    }

    // Phase C.
    if !internal && sign {
        m = Some(if sigma == Some(Scheme::PgpInline) {
            "text/plain".into()
        } else {
            "multipart/mixed".into()
        });
    } else if composer_mime == "text/plain" {
        m = Some("text/plain".into());
    }

    // Phase D.
    let scheme_val = if internal {
        scheme::INTERNAL
    } else if sign && e {
        if sigma == Some(Scheme::PgpInline) {
            scheme::PGP_INLINE
        } else {
            scheme::PGP_MIME
        }
    } else if sign {
        if sigma == Some(Scheme::PgpInline) {
            scheme::CLEAR
        } else {
            scheme::CLEAR_MIME
        }
    } else {
        scheme::CLEAR
    };

    let mut mime_type = m.unwrap_or_default();
    if mime_type.is_empty() {
        mime_type = composer_mime.to_string();
    }
    Ok(SendPreferences {
        encrypt: e,
        sign,
        scheme: scheme_val,
        signature_type: if sign {
            signature_type::DETACHED
        } else {
            signature_type::NONE
        },
        mime_type,
        pub_key: k,
        internal,
    })
}

/// Recipient lookup failure: the address does not exist (code 33102).
#[derive(Debug, Clone, thiserror::Error)]
#[error("recipient address does not exist: {0}")]
pub struct RecipientDoesNotExist(pub String);

/// Resolve preferences for one recipient (key lookup, contact settings,
/// computation).
pub async fn resolve(
    ctx: &AccountContext,
    email: &str,
    composer_mime: &str,
    settings: &MailSettings,
) -> Result<SendPreferences> {
    let keys = match ctx.client.get_public_keys(email).await {
        Ok(k) => k,
        Err(e) if e.api().is_some_and(|a| a.status == 422 && a.code == 33102) => {
            return Err(Error::NotFound(format!("recipient:{email}")));
        }
        Err(e) => return Err(e),
    };
    let contact = contact_settings(ctx, email).await;
    compute(&keys, &contact, settings, composer_mime)
}

async fn contact_settings(ctx: &AccountContext, email: &str) -> ContactSettings {
    let emails = match ctx.client.get_contact_emails(email).await {
        Ok(e) => e,
        Err(_) => return ContactSettings::default(),
    };
    let Some(ce) = emails.into_iter().find(|c| c.email == email) else {
        return ContactSettings::default();
    };
    match ctx.client.get_contact(&ce.contact_id).await {
        Ok(c) => contact_settings_from_cards(&c.cards, &ctx.user_ring(), email),
        Err(_) => ContactSettings::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::PublicKeys;

    #[test]
    fn vcard_groups() {
        let v = "BEGIN:VCARD\r\nVERSION:4.0\r\nitem1.EMAIL;PREF=1:bob@x.org\r\nitem1.X-PM-SCHEME:pgp-inline\r\nitem1.X-PM-SIGN:true\r\nitem2.EMAIL:other@x.org\r\nitem2.X-PM-ENCRYPT:true\r\nEND:VCARD\r\n";
        let s = parse_vcard_settings(v, "bob@x.org").unwrap();
        assert_eq!(s.scheme.as_deref(), Some("pgp-inline"));
        assert_eq!(s.sign, Some(true));
        assert_eq!(s.encrypt, None);
        assert!(s.encrypt_untrusted);
        assert!(parse_vcard_settings(v, "nobody@x.org").is_none());
    }

    #[test]
    fn external_no_keys_defaults() {
        let keys = PublicKeys {
            keys: vec![],
            recipient_type: 2,
        };
        let settings = MailSettings {
            draft_mime_type: "text/html".into(),
            ..Default::default()
        };
        let p = compute(&keys, &ContactSettings::default(), &settings, "text/html").unwrap();
        assert_eq!(p.scheme, scheme::CLEAR);
        assert!(!p.encrypt && !p.sign);
        assert_eq!(p.mime_type, "text/html");
        assert_eq!(p.signature_type, 0);
    }

    #[test]
    fn external_sign_by_default() {
        let keys = PublicKeys {
            keys: vec![],
            recipient_type: 2,
        };
        let settings = MailSettings {
            draft_mime_type: "text/html".into(),
            sign: 1,
            ..Default::default()
        };
        let p = compute(&keys, &ContactSettings::default(), &settings, "text/html").unwrap();
        assert_eq!(p.scheme, scheme::CLEAR_MIME);
        assert_eq!(p.mime_type, "multipart/mixed");
        assert_eq!(p.signature_type, 1);
    }

    #[test]
    fn internal_requires_keys() {
        let keys = PublicKeys {
            keys: vec![],
            recipient_type: 1,
        };
        assert!(
            compute(
                &keys,
                &ContactSettings::default(),
                &MailSettings::default(),
                "text/html"
            )
            .is_err()
        );
    }
}
