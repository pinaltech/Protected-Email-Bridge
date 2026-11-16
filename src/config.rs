//! Deployment constants (§3.1), local artifacts (§3.2) and default values
//! and limits (Appendix B).

use std::time::Duration;

/// Values fixed by the Service operator (§3.1). The specification refers to
/// them symbolically; they MUST be supplied by the embedding application.
#[derive(Debug, Clone)]
pub struct DeploymentConfig {
    /// `API_BASE_URL` — absolute HTTPS base URL of the Service API.
    pub api_base_url: String,
    /// `MODULUS_SIGNING_KEY` — armored public key that clear-signs SRP moduli.
    pub modulus_signing_key: String,
    /// `SRP_SALT_SUFFIX` — fixed 6-octet ASCII suffix (password versions 3/4).
    pub srp_salt_suffix: [u8; 6],
    /// `REFRESH_REDIRECT_URI` — sent in token refresh requests.
    pub refresh_redirect_uri: String,
    /// `APP_PRODUCT_TOKEN` — embedded in `x-pm-appversion`.
    pub app_product_token: String,
    /// Application semantic version embedded in `x-pm-appversion`.
    pub app_version: String,
    /// The platform embedded in `x-pm-appversion` in place of the one this
    /// build runs on (`platform_token`); `None` (or blank) keeps that one.
    pub app_platform: Option<String>,
    /// Product name used in the IMAP greeting / ID response.
    pub product_name: String,
    /// `API_TLS_PINS` — optional base64 SHA-256 SPKI pins.
    pub api_tls_pins: Vec<String>,
}

impl DeploymentConfig {
    /// `<platform>-<APP_PRODUCT_TOKEN>@<semver>` (§4.2).
    pub fn app_version_header(&self) -> String {
        format!(
            "{}-{}@{}",
            self.platform(),
            self.app_product_token,
            self.app_version
        )
    }

    /// The platform `x-pm-appversion` names: `app_platform` when set, else
    /// the one this build runs on.
    pub fn platform(&self) -> &str {
        self.app_platform
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .unwrap_or(platform_token())
    }
}

/// `linux`, `macos` or `windows`.
pub fn platform_token() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    }
}

/// Identifiers visible only between the Gateway and its Clients (§3.2).
#[derive(Debug, Clone)]
pub struct LocalArtifacts {
    pub hdr_internal_id: String,
    pub hdr_external_id: String,
    pub hdr_server_date: String,
    pub hdr_local_id: String,
    pub internal_id_domain: String,
    pub recovery_mailbox: String,
}

impl Default for LocalArtifacts {
    fn default() -> Self {
        Self {
            hdr_internal_id: "X-Gw-Internal-Id".into(),
            hdr_external_id: "X-Gw-External-Id".into(),
            hdr_server_date: "X-Gw-Date".into(),
            hdr_local_id: "X-Gw-Local-Id".into(),
            internal_id_domain: "internal.invalid".into(),
            recovery_mailbox: "Recovered Messages".into(),
        }
    }
}

/// Listener security mode (§11.1, §13.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ListenerSecurity {
    /// TLS from the first octet.
    ImplicitTls,
    /// Plaintext with STARTTLS (default).
    #[default]
    StartTls,
}

/// User-tunable gateway settings.
#[derive(Debug, Clone)]
pub struct GatewaySettings {
    pub show_all_mail: bool,
    pub imap_security: ListenerSecurity,
    pub smtp_security: ListenerSecurity,
    pub imap_port: Option<u16>,
    pub smtp_port: Option<u16>,
    pub imap_idle_enabled: bool,
    pub imap_authenticate_enabled: bool,
    pub imap_login_jail: Duration,
    /// Maximum sync memory in bytes (clamped per §12.1).
    pub max_sync_memory: u64,
    /// Maximum parallel downloads during sync.
    pub max_sync_parallelism: usize,
}

impl Default for GatewaySettings {
    fn default() -> Self {
        Self {
            show_all_mail: true,
            imap_security: ListenerSecurity::StartTls,
            smtp_security: ListenerSecurity::StartTls,
            imap_port: None,
            smtp_port: None,
            imap_idle_enabled: true,
            imap_authenticate_enabled: true,
            imap_login_jail: Duration::ZERO,
            max_sync_memory: limits::SYNC_MEMORY_DEFAULT,
            max_sync_parallelism: limits::SYNC_MAX_PARALLEL_DOWNLOADS,
        }
    }
}

/// Default values and limits (Appendix B).
pub mod limits {
    use std::time::Duration;

    pub const MIB: u64 = 1024 * 1024;
    pub const GIB: u64 = 1024 * MIB;

    pub const IMAP_PORT_BASE: u16 = 1143;
    pub const SMTP_PORT_BASE: u16 = 1025;

    pub const EVENT_POLL_BASE: Duration = Duration::from_secs(20);
    pub const EVENT_POLL_JITTER: Duration = Duration::from_secs(20);
    pub const EVENT_CHAIN_CAP: usize = 50;

    pub const APP_BACKOFF_SEQUENCE: [u64; 6] = [20, 40, 80, 160, 300, 600];
    pub const BACKOFF_JITTER_SECS: u64 = 10;

    pub const TRANSPORT_RETRIES: usize = 3;
    pub const RETRY_AFTER_DEFAULT: Duration = Duration::from_secs(10);
    pub const RETRY_WAIT_CAP: Duration = Duration::from_secs(60);

    pub const SYNC_RETRY_COOLDOWN: Duration = Duration::from_secs(20);
    pub const SYNC_METADATA_PAGE: usize = 128;
    pub const SYNC_BATCH_MESSAGES: usize = 64;
    pub const SYNC_MAX_PARALLEL_DOWNLOADS: usize = 64;
    pub const SYNC_MEMORY_DEFAULT: u64 = 2 * GIB;
    pub const SYNC_MEMORY_MIN: u64 = 800 * MIB;

    pub const LIST_PAGE_SIZE: usize = 150;
    pub const BULK_ACTION_CHUNK: usize = 150;
    pub const ID_ENUMERATION_PAGE: usize = 1000;

    pub const IMPORT_BATCH_MESSAGES: usize = 10;
    pub const IMPORT_BATCH_BYTES: u64 = 70 * MIB;
    pub const IMPORT_MESSAGE_CAP: u64 = 70 * MIB;

    pub const SEND_DEDUP_LIFETIME: Duration = Duration::from_secs(30 * 60);
    pub const SEND_DEDUP_WAIT: Duration = Duration::from_secs(90);

    pub const SMTP_FAILURE_WINDOW: Duration = Duration::from_secs(1);
    pub const SMTP_FAILURE_THRESHOLD: u32 = 3;
    pub const SMTP_FAILURE_LOCKOUT: Duration = Duration::from_secs(20);
    pub const SMTP_MAX_LINE: usize = 65_536;
    pub const SMTP_MAX_SYNTAX_ERRORS: u32 = 3;

    pub const IMAP_LOGIN_FAILURES: u32 = 3;
    pub const IMAP_SESSION_ERROR_CAP: u32 = 20;
    pub const IMAP_IDLE_BATCH: Duration = Duration::from_millis(500);
    pub const IMAP_NEW_CONNECTION_CAP: usize = 400;
    pub const IMAP_CONNECTION_WINDOW_BUCKETS: usize = 6;
    pub const IMAP_CONNECTION_BUCKET: Duration = Duration::from_secs(10);
    pub const APPLE_MAIL_SESSION_CAP: usize = 60;
    pub const APPLE_MAIL_SESSION_CAP_FALLBACK: usize = 25;

    /// 2023-02-01T00:00:00Z.
    pub const UIDVALIDITY_EPOCH: i64 = 1_675_209_600;

    pub const NEW_LABEL_COLOR: &str = "#f66";

    pub const TLS_CERT_VALIDITY_YEARS: i32 = 20;
    pub const TLS_CERT_RENEW_DAYS: i64 = 31;

    pub const GATEWAY_PASSWORD_LEN: usize = 16;

    pub const SRP_BITS: u64 = 2048;
    pub const SRP_LEN: usize = 256;

    pub const BCRYPT_COST: u32 = 10;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(app_platform: Option<&str>) -> DeploymentConfig {
        DeploymentConfig {
            api_base_url: "https://api.example/".into(),
            modulus_signing_key: String::new(),
            srp_salt_suffix: *b"suffix",
            refresh_redirect_uri: "https://example/".into(),
            app_product_token: "app".into(),
            app_version: "1.2.3".into(),
            app_platform: app_platform.map(Into::into),
            product_name: "App".into(),
            api_tls_pins: Vec::new(),
        }
    }

    #[test]
    fn app_version_header_names_the_platform_given_or_this_one() {
        let own = format!("{}-app@1.2.3", platform_token());
        assert_eq!(config(None).app_version_header(), own);
        assert_eq!(config(Some(" ")).app_version_header(), own);
        assert_eq!(config(Some("windows")).app_version_header(), "windows-app@1.2.3");
    }
}
