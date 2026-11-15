//! Small shared helpers: IntBool serde, Base64 flavours, randomness, email
//! comparison and date formatting.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::{DateTime, TimeZone, Utc};
use rand::{Rng, RngExt};
use std::time::Duration;

/// Standard Base64 with padding (B64).
pub fn b64(data: impl AsRef<[u8]>) -> String {
    STANDARD.encode(data)
}

/// Decode standard Base64 (B64).
pub fn b64_decode(data: impl AsRef<[u8]>) -> crate::Result<Vec<u8>> {
    Ok(STANDARD.decode(data)?)
}

/// URL-safe Base64 without padding (B64URL-NP).
pub fn b64url_np(data: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decode URL-safe Base64 without padding (B64URL-NP).
pub fn b64url_np_decode(data: impl AsRef<[u8]>) -> crate::Result<Vec<u8>> {
    Ok(URL_SAFE_NO_PAD.decode(data)?)
}

/// Base64 wrapped at 76 columns with CRLF line endings (MIME bodies).
pub fn b64_wrapped(data: impl AsRef<[u8]>) -> String {
    let encoded = b64(data);
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 76 * 2 + 2);
    for chunk in encoded.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push_str("\r\n");
    }
    out
}

/// `n` octets from a CSPRNG.
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::rng().fill_bytes(&mut buf);
    buf
}

/// Lowercase hex of `n` random octets.
pub fn random_hex(n: usize) -> String {
    hex::encode(random_bytes(n))
}

/// A MIME boundary: 64 lowercase hex characters (32 random octets, §11.8.3).
pub fn mime_boundary() -> String {
    random_hex(32)
}

/// Uniform random duration in `[0, max)`.
pub fn jitter(max: Duration) -> Duration {
    if max.is_zero() {
        return Duration::ZERO;
    }
    let ms = rand::rng().random_range(0..max.as_millis() as u64);
    Duration::from_millis(ms)
}

/// Normalise an email for comparison with owned addresses (§7.2): lowercase
/// and strip a `+tag` sub-address suffix from the local part.
pub fn canonical_email(email: &str) -> String {
    let email = email.trim().to_lowercase();
    match email.rsplit_once('@') {
        Some((local, domain)) => {
            let local = local.split_once('+').map(|(l, _)| l).unwrap_or(local);
            format!("{local}@{domain}")
        }
        None => email,
    }
}

/// Compare two emails case-insensitively with `+tag` stripping.
pub fn emails_match(a: &str, b: &str) -> bool {
    canonical_email(a) == canonical_email(b)
}

/// Returns the `+tag` part (without `+`) of an address's local part, if any.
pub fn plus_tag(email: &str) -> Option<&str> {
    let (local, _) = email.rsplit_once('@')?;
    local.split_once('+').map(|(_, tag)| tag)
}

/// RFC 1123Z formatted date (`Mon, 02 Jan 2006 15:04:05 -0700`), in UTC.
pub fn rfc1123z(dt: DateTime<Utc>) -> String {
    dt.format("%a, %d %b %Y %H:%M:%S %z").to_string()
}

/// RFC 1123Z formatted unix timestamp (UTC).
pub fn rfc1123z_ts(ts: i64) -> String {
    rfc1123z(Utc.timestamp_opt(ts, 0).single().unwrap_or_default())
}

/// Current unix time in seconds.
pub fn now_unix() -> i64 {
    Utc::now().timestamp()
}

/// Strip surrounding angle brackets and whitespace from a message id.
pub fn strip_angles(s: &str) -> String {
    s.trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim()
        .to_string()
}

/// Serde helpers for the IntBool encoding (§2): booleans as `0`/`1`.
pub mod intbool {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &bool, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(u8::from(*v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Int(i64),
            Bool(bool),
            Null(()),
        }
        Ok(match Raw::deserialize(d)? {
            Raw::Int(i) => i != 0,
            Raw::Bool(b) => b,
            Raw::Null(()) => false,
        })
    }
}

/// Deserialize `null` as the type's default.
pub fn null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de> + Default,
{
    use serde::Deserialize;
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical() {
        assert_eq!(canonical_email("User+tag@Example.COM"), "user@example.com");
        assert!(emails_match("a+x@d", "A@D"));
        assert_eq!(plus_tag("a+x@d"), Some("x"));
    }

    #[test]
    fn boundary_len() {
        assert_eq!(mime_boundary().len(), 64);
    }

    #[test]
    fn date_fmt() {
        assert_eq!(rfc1123z_ts(0), "Thu, 01 Jan 1970 00:00:00 +0000");
    }
}
