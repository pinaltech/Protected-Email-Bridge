//! Certificate pinning for the API endpoints and their proxies (§4.10).
//!
//! A pin is the standard Base64 encoding of the SHA-256 digest of a
//! certificate's DER-encoded `SubjectPublicKeyInfo` (the HPKP format). The
//! connection is accepted only if normal certificate validation succeeds
//! **and** at least one certificate in the presented chain (leaf or
//! intermediate) carries a pinned public key.

use std::fmt;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::util::{b64, b64_decode};

/// Details of a pin mismatch, passed to the failure hook so the embedder
/// can report it to the Service (§4.10: "MAY report the failure").
#[derive(Debug, Clone)]
pub struct PinFailure {
    /// Server name the client tried to reach.
    pub host: String,
    /// Base64 SPKI SHA-256 hashes of every certificate presented.
    pub presented: Vec<String>,
    /// DER of every certificate presented (leaf first).
    pub chain_der: Vec<Vec<u8>>,
}

/// Callback invoked on every pin mismatch.
pub type PinFailureHook = Arc<dyn Fn(&PinFailure) + Send + Sync>;

/// SHA-256 of a certificate's DER-encoded SubjectPublicKeyInfo.
pub fn spki_sha256(cert_der: &[u8]) -> Option<[u8; 32]> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).ok()?;
    Some(Sha256::digest(cert.tbs_certificate.subject_pki.raw).into())
}

/// Parse Base64 pins into raw digests. Invalid entries are an error, so a
/// typo cannot silently disable pinning.
pub fn parse_pins(pins: &[String]) -> Result<Vec<[u8; 32]>> {
    pins.iter()
        .map(|p| {
            let raw = b64_decode(p.trim())?;
            <[u8; 32]>::try_from(raw.as_slice())
                .map_err(|_| Error::Invalid(format!("TLS pin {p:?} is not a SHA-256 digest")))
        })
        .collect()
}

/// Server certificate verifier: platform validation plus SPKI pinning.
pub struct PinningVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    pins: Vec<[u8; 32]>,
    on_failure: Option<PinFailureHook>,
}

impl fmt::Debug for PinningVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinningVerifier")
            .field("pins", &self.pins.len())
            .finish_non_exhaustive()
    }
}

impl PinningVerifier {
    /// Wrap `inner` (normally the platform verifier) with pin checks.
    pub fn new(
        inner: Arc<dyn ServerCertVerifier>,
        pins: Vec<[u8; 32]>,
        on_failure: Option<PinFailureHook>,
    ) -> Self {
        Self {
            inner,
            pins,
            on_failure,
        }
    }

    /// True if any certificate of the chain carries a pinned key.
    pub fn chain_matches(&self, chain: &[&[u8]]) -> bool {
        chain
            .iter()
            .filter_map(|c| spki_sha256(c))
            .any(|h| self.pins.contains(&h))
    }
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let verified = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let chain: Vec<&[u8]> = std::iter::once(end_entity.as_ref())
            .chain(intermediates.iter().map(|c| c.as_ref()))
            .collect();
        if self.chain_matches(&chain) {
            return Ok(verified);
        }
        let failure = PinFailure {
            host: server_name.to_str().into_owned(),
            presented: chain
                .iter()
                .filter_map(|c| spki_sha256(c).map(b64))
                .collect(),
            chain_der: chain.iter().map(|c| c.to_vec()).collect(),
        };
        tracing::error!(host = %failure.host, "API certificate pin mismatch; refusing connection");
        if let Some(hook) = &self.on_failure {
            hook(&failure);
        }
        Err(rustls::Error::InvalidCertificate(
            CertificateError::ApplicationVerificationFailure,
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Build a rustls client configuration that validates certificates with
/// the OS trust store and enforces `pins`.
pub fn pinned_client_config(
    pins: &[String],
    on_failure: Option<PinFailureHook>,
) -> Result<ClientConfig> {
    let pins = parse_pins(pins)?;
    if pins.is_empty() {
        return Err(Error::Invalid("no TLS pins configured".into()));
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let platform = rustls_platform_verifier::Verifier::new(provider.clone())
        .map_err(|e| Error::Tls(e.to_string()))?;
    let verifier = PinningVerifier::new(Arc::new(platform), pins, on_failure);
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair, PublicKeyData};

    fn cert() -> (Vec<u8>, Vec<u8>) {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = CertificateParams::new(vec!["api.example".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        (cert.der().to_vec(), key.subject_public_key_info())
    }

    /// Verifier that accepts everything, to isolate the pin logic.
    #[derive(Debug)]
    struct AcceptAll;
    impl ServerCertVerifier for AcceptAll {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![]
        }
    }

    #[test]
    fn spki_hash_matches_public_key_der() {
        let (der, spki) = cert();
        let expected: [u8; 32] = Sha256::digest(&spki).into();
        assert_eq!(spki_sha256(&der), Some(expected));
    }

    #[test]
    fn pin_enforced() {
        let (leaf, spki) = cert();
        let (other, _) = cert();
        let pin: [u8; 32] = Sha256::digest(&spki).into();
        let failures = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let f2 = failures.clone();
        let v = PinningVerifier::new(
            Arc::new(AcceptAll),
            vec![pin],
            Some(Arc::new(move |_| {
                f2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })),
        );
        let name = ServerName::try_from("api.example").unwrap();
        let now = UnixTime::now();
        // Pinned leaf.
        assert!(
            v.verify_server_cert(&CertificateDer::from(leaf.clone()), &[], &name, &[], now)
                .is_ok()
        );
        // Pinned key appearing as an intermediate.
        assert!(
            v.verify_server_cert(
                &CertificateDer::from(other.clone()),
                &[CertificateDer::from(leaf)],
                &name,
                &[],
                now
            )
            .is_ok()
        );
        // No pinned key in the chain.
        assert!(
            v.verify_server_cert(&CertificateDer::from(other), &[], &name, &[], now)
                .is_err()
        );
        assert_eq!(failures.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn pin_parsing() {
        assert!(parse_pins(&[b64([1u8; 32])]).is_ok());
        assert!(parse_pins(&["not-base64!".into()]).is_err());
        assert!(parse_pins(&[b64([1u8; 16])]).is_err());
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        assert!(pinned_client_config(&[b64([1u8; 32])], None).is_ok());
    }
}
