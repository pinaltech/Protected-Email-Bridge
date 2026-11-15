//! Listener certificate (§11.1): a self-signed RSA-2048 certificate for
//! `127.0.0.1`, valid 20 years, regenerated when it expires within 31 days.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use chrono::{Datelike, Utc};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType, date_time_ymd,
};
use serde::{Deserialize, Serialize};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::config::limits::{TLS_CERT_RENEW_DAYS, TLS_CERT_VALIDITY_YEARS};
use crate::error::{Error, Result};

/// A certificate and key, plus the expiry needed for renewal checks.
#[derive(Clone, Serialize, Deserialize)]
pub struct TlsIdentity {
    pub cert_der: Vec<u8>,
    pub key_pkcs8_der: Vec<u8>,
    pub not_after_unix: i64,
}

impl std::fmt::Debug for TlsIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsIdentity")
            .field("not_after_unix", &self.not_after_unix)
            .finish_non_exhaustive()
    }
}

impl TlsIdentity {
    /// Generate a new self-signed certificate.
    pub fn generate() -> Result<Self> {
        let tls_err = |e: rcgen::Error| Error::Tls(e.to_string());
        let key = KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).map_err(tls_err)?;
        let mut params = CertificateParams::new(Vec::<String>::new()).map_err(tls_err)?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "127.0.0.1");
        params.distinguished_name = dn;
        params.subject_alt_names = vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))];
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyEncipherment,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
        ];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let now = Utc::now();
        let (y, m, d) = (now.year(), now.month() as u8, now.day().min(28) as u8);
        params.not_before = date_time_ymd(y, m, d);
        let end_year = y + TLS_CERT_VALIDITY_YEARS;
        params.not_after = date_time_ymd(end_year, m, d);
        let cert = params.self_signed(&key).map_err(tls_err)?;
        let not_after_unix = chrono::NaiveDate::from_ymd_opt(end_year, m as u32, d as u32)
            .and_then(|nd| nd.and_hms_opt(0, 0, 0))
            .map(|ndt| ndt.and_utc().timestamp())
            .unwrap_or(i64::MAX);
        Ok(Self {
            cert_der: cert.der().to_vec(),
            key_pkcs8_der: key.serialize_der(),
            not_after_unix,
        })
    }

    /// True if the certificate expires within 31 days.
    pub fn needs_renewal(&self) -> bool {
        self.not_after_unix - Utc::now().timestamp() < TLS_CERT_RENEW_DAYS * 86_400
    }

    /// Return `existing` unless it must be renewed.
    pub fn load_or_generate(existing: Option<TlsIdentity>) -> Result<Self> {
        match existing {
            Some(id) if !id.needs_renewal() => Ok(id),
            _ => Self::generate(),
        }
    }

    /// Build a TLS acceptor for the listeners.
    pub fn acceptor(&self) -> Result<TlsAcceptor> {
        let cert = CertificateDer::from(self.cert_der.clone());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_pkcs8_der.clone()));
        let cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(|e| Error::Tls(e.to_string()))?;
        Ok(TlsAcceptor::from(Arc::new(cfg)))
    }

    /// PEM of the certificate (for exporting to clients' trust stores).
    pub fn cert_pem(&self) -> String {
        let b64 = crate::util::b64(&self.cert_der);
        let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
        out
    }
}

/// First free port on 127.0.0.1 at or above `base`, skipping `exclude`.
pub fn first_free_port(base: u16, exclude: Option<u16>) -> Option<u16> {
    (base..=u16::MAX).find(|p| {
        Some(*p) != exclude && std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, *p)).is_ok()
    })
}
