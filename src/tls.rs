//! Listener TLS (§11.1): a self-signed RSA-2048 certificate for
//! `127.0.0.1`, valid 20 years, regenerated when it expires within 31 days.
//!
//! TLS parameters: minimum protocol version TLS 1.2 (TLS 1.2 and 1.3 are
//! offered), and the server never requests client certificates. One
//! [`ServerConfig`] is shared by the IMAP and SMTP listeners, for both
//! implicit TLS and STARTTLS.

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

/// Protocol versions offered by the listeners: TLS 1.3 and TLS 1.2 (the
/// minimum, §11.1).
pub static LISTENER_TLS_VERSIONS: &[&tokio_rustls::rustls::SupportedProtocolVersion] = &[
    &tokio_rustls::rustls::version::TLS13,
    &tokio_rustls::rustls::version::TLS12,
];
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

    /// The shared listener TLS configuration (§11.1): TLS 1.2 minimum, no
    /// client certificate request.
    pub fn server_config(&self) -> Result<Arc<ServerConfig>> {
        let cert = CertificateDer::from(self.cert_der.clone());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_pkcs8_der.clone()));
        let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
        let cfg = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(LISTENER_TLS_VERSIONS)
            .map_err(|e| Error::Tls(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(|e| Error::Tls(e.to_string()))?;
        Ok(Arc::new(cfg))
    }

    /// A TLS acceptor over [`server_config`](Self::server_config). Build it
    /// once and hand clones to both listeners so they share one
    /// configuration.
    pub fn acceptor(&self) -> Result<TlsAcceptor> {
        Ok(TlsAcceptor::from(self.server_config()?))
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use tokio_rustls::rustls::pki_types::{ServerName, UnixTime};
    use tokio_rustls::rustls::{
        ClientConfig, DigitallySignedStruct, ProtocolVersion, SignatureScheme,
        SupportedProtocolVersion, version,
    };

    /// The listener certificate is self-signed; accept it for the test.
    #[derive(Debug)]
    struct TrustAll;
    impl ServerCertVerifier for TrustAll {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> std::result::Result<ServerCertVerified, tokio_rustls::rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    /// Handshake with a client limited to `versions` that also holds a
    /// client certificate. Returns (negotiated version, whether the server
    /// received a client certificate).
    async fn handshake(
        id: &TlsIdentity,
        versions: &[&'static SupportedProtocolVersion],
    ) -> (ProtocolVersion, bool) {
        let acceptor = id.acceptor().unwrap();
        let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
        let client_cert = CertificateDer::from(id.cert_der.clone());
        let client_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key_pkcs8_der.clone()));
        let cfg = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(TrustAll))
            .with_client_auth_cert(vec![client_cert], client_key)
            .unwrap();
        let connector = TlsConnector::from(Arc::new(cfg));
        let (c, s) = tokio::io::duplex(64 * 1024);
        let name = ServerName::try_from("127.0.0.1").unwrap().to_owned();
        let (client, server) = tokio::join!(connector.connect(name, c), acceptor.accept(s));
        let client = client.unwrap();
        let server = server.unwrap();
        let v = client.get_ref().1.protocol_version().unwrap();
        (v, server.get_ref().1.peer_certificates().is_some())
    }

    #[tokio::test]
    async fn listener_tls_parameters() {
        let id = TlsIdentity::generate().unwrap();
        assert!(!id.needs_renewal());
        let (v12, cert12) = handshake(&id, &[&version::TLS12]).await;
        assert_eq!(v12, ProtocolVersion::TLSv1_2);
        assert!(!cert12, "server must not request client certificates");
        let (v13, cert13) = handshake(&id, &[&version::TLS13]).await;
        assert_eq!(v13, ProtocolVersion::TLSv1_3);
        assert!(!cert13, "server must not request client certificates");
    }
}
