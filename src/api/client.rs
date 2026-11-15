//! Remote API transport (§4): headers, retries, token refresh, connectivity
//! tracking and clock synchronisation.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;

use reqwest::{Method, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::sync::{Mutex, RwLock, watch};
use tracing::{debug, warn};

use crate::config::{DeploymentConfig, limits};
use crate::error::{ApiError, Error, Result};
use crate::util::{b64, jitter, random_bytes};

/// Session credentials held by the client.
#[derive(Debug, Clone, Default)]
pub struct SessionTokens {
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
}

/// Human-verification headers to attach to login-phase requests (§5.3).
#[derive(Debug, Clone)]
pub struct HumanVerification {
    pub token: String,
    pub methods: Vec<String>,
}

/// Callback invoked whenever the client obtains new tokens (§4.7 step 4).
pub type TokenListener = Arc<dyn Fn(&SessionTokens) + Send + Sync>;
/// Callback invoked once per session when it is irrecoverably dead (§4.7).
pub type DeauthListener = Arc<dyn Fn() + Send + Sync>;

/// One part of a `multipart/form-data` body. Kept as plain data so that the
/// request can be rebuilt for each retry.
#[derive(Debug, Clone)]
pub struct FormPart {
    pub name: String,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub data: Vec<u8>,
}

impl FormPart {
    pub fn text(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            filename: None,
            content_type: None,
            data: value.into().into_bytes(),
        }
    }

    pub fn file(
        name: impl Into<String>,
        filename: impl Into<String>,
        content_type: impl Into<String>,
        data: Vec<u8>,
    ) -> Self {
        Self {
            name: name.into(),
            filename: Some(filename.into()),
            content_type: Some(content_type.into()),
            data,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum Body {
    None,
    Json(Value),
    Multipart(Vec<FormPart>),
}

/// A request description.
#[derive(Debug, Clone)]
pub(crate) struct Request {
    pub method: Method,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Body,
    pub authenticated: bool,
}

impl Request {
    pub fn new(method: Method, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            query: Vec::new(),
            headers: Vec::new(),
            body: Body::None,
            authenticated: true,
        }
    }
    pub fn get(path: impl Into<String>) -> Self {
        Self::new(Method::GET, path)
    }
    pub fn post(path: impl Into<String>) -> Self {
        Self::new(Method::POST, path)
    }
    pub fn put(path: impl Into<String>) -> Self {
        Self::new(Method::PUT, path)
    }
    pub fn delete(path: impl Into<String>) -> Self {
        Self::new(Method::DELETE, path)
    }
    pub fn json(mut self, body: impl Serialize) -> Self {
        self.body = Body::Json(serde_json::to_value(body).unwrap_or(Value::Null));
        self
    }
    pub fn multipart(mut self, parts: Vec<FormPart>) -> Self {
        self.body = Body::Multipart(parts);
        self
    }
    pub fn query(mut self, k: impl Into<String>, v: impl ToString) -> Self {
        self.query.push((k.into(), v.to_string()));
        self
    }
    pub fn header(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }
    pub fn unauthenticated(mut self) -> Self {
        self.authenticated = false;
        self
    }
}

/// A raw successful response.
#[derive(Debug)]
pub(crate) struct RawResponse {
    pub body: Vec<u8>,
}

impl RawResponse {
    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        Ok(serde_json::from_slice(&self.body)?)
    }
}

const DEFAULT_USER_AGENT: &str = "NoClient/0.0.1";
const UNKNOWN_SMTP_AGENT: &str = "UnknownClient/0.0.1";

/// Options for [`ApiClient::with_options`].
#[derive(Clone, Default)]
pub struct ClientOptions {
    /// Called on every certificate pin mismatch, e.g. to report it to the
    /// Service (§4.10). The connection is refused regardless.
    pub pin_failure: Option<super::pinning::PinFailureHook>,
}

/// Authenticated HTTPS/JSON client for the Service.
#[derive(Clone)]
pub struct ApiClient {
    inner: Arc<Inner>,
}

struct Inner {
    http: reqwest::Client,
    cfg: Arc<DeploymentConfig>,
    tokens: RwLock<SessionTokens>,
    refresh_lock: Mutex<()>,
    user_agent: RwLock<String>,
    hv: RwLock<Option<HumanVerification>>,
    connectivity: watch::Sender<bool>,
    clock_offset: AtomicI64,
    deauth_fired: AtomicBool,
    token_listener: RwLock<Option<TokenListener>>,
    deauth_listener: RwLock<Option<DeauthListener>>,
}

impl ApiClient {
    /// Create a new unauthenticated client. If `API_TLS_PINS` is configured,
    /// certificate pinning (§4.10) is enforced on every connection.
    pub fn new(cfg: Arc<DeploymentConfig>) -> Result<Self> {
        Self::with_options(cfg, ClientOptions::default())
    }

    /// Create a client with extra options (e.g. a pin-failure hook).
    pub fn with_options(cfg: Arc<DeploymentConfig>, opts: ClientOptions) -> Result<Self> {
        let mut builder = reqwest::Client::builder()
            .https_only(cfg.api_base_url.starts_with("https://"))
            .connect_timeout(Duration::from_secs(30));
        if !cfg.api_tls_pins.is_empty() {
            let tls = super::pinning::pinned_client_config(&cfg.api_tls_pins, opts.pin_failure)?;
            builder = builder.tls_backend_preconfigured(tls);
        }
        let http = builder.build().map_err(|e| Error::Network(e.to_string()))?;
        let (tx, _rx) = watch::channel(true);
        Ok(Self {
            inner: Arc::new(Inner {
                http,
                cfg,
                tokens: RwLock::new(SessionTokens::default()),
                refresh_lock: Mutex::new(()),
                user_agent: RwLock::new(format!("{DEFAULT_USER_AGENT} ({})", os_name())),
                hv: RwLock::new(None),
                connectivity: tx,
                clock_offset: AtomicI64::new(0),
                deauth_fired: AtomicBool::new(false),
                token_listener: RwLock::new(None),
                deauth_listener: RwLock::new(None),
            }),
        })
    }

    pub fn config(&self) -> &DeploymentConfig {
        &self.inner.cfg
    }

    /// Install the session tokens (after login or when resuming).
    pub async fn set_tokens(&self, tokens: SessionTokens) {
        *self.inner.tokens.write().await = tokens;
        self.inner.deauth_fired.store(false, Ordering::SeqCst);
    }

    pub async fn tokens(&self) -> SessionTokens {
        self.inner.tokens.read().await.clone()
    }

    pub async fn clear_tokens(&self) {
        *self.inner.tokens.write().await = SessionTokens::default();
    }

    pub async fn set_token_listener(&self, l: TokenListener) {
        *self.inner.token_listener.write().await = Some(l);
    }

    pub async fn set_deauth_listener(&self, l: DeauthListener) {
        *self.inner.deauth_listener.write().await = Some(l);
    }

    pub async fn set_human_verification(&self, hv: Option<HumanVerification>) {
        *self.inner.hv.write().await = hv;
    }

    /// Record the identity of the most recent mail client (§4.2).
    /// Identification strings from note-taking agents are ignored.
    pub async fn set_client_identity(&self, name: &str, version: &str) {
        let lname = name.to_lowercase();
        if lname.contains("notes") {
            return;
        }
        let version = fold_version(version);
        *self.inner.user_agent.write().await = format!("{name}/{version} ({})", os_name());
    }

    /// Called when an SMTP session authenticates: substitutes
    /// `UnknownClient/0.0.1` while the agent is still the default.
    pub async fn note_smtp_auth(&self) {
        let mut ua = self.inner.user_agent.write().await;
        if ua.starts_with(DEFAULT_USER_AGENT) {
            *ua = format!("{UNKNOWN_SMTP_AGENT} ({})", os_name());
        }
    }

    pub async fn user_agent(&self) -> String {
        self.inner.user_agent.read().await.clone()
    }

    /// Current connectivity state (§4.8).
    pub fn is_connected(&self) -> bool {
        *self.inner.connectivity.borrow()
    }

    /// Subscribe to connectivity changes.
    pub fn connectivity(&self) -> watch::Receiver<bool> {
        self.inner.connectivity.subscribe()
    }

    /// The Service-synchronised current unix time (§4.3).
    pub fn server_now(&self) -> i64 {
        crate::util::now_unix() + self.inner.clock_offset.load(Ordering::Relaxed)
    }

    fn set_connected(&self, up: bool) {
        self.inner.connectivity.send_if_modified(|v| {
            if *v != up {
                *v = up;
                true
            } else {
                false
            }
        });
    }

    /// `GET /tests/ping` probe: any HTTP response counts as reachable.
    pub async fn ping(&self) -> bool {
        let req = Request::get("/tests/ping").unauthenticated();
        match self.execute_once(&req, None).await {
            Ok(_) => true,
            Err(Error::Api(_)) => true,
            Err(_) => false,
        }
    }

    // ---- execution -------------------------------------------------------

    /// Execute a request, applying transport-level retry (§4.5) and access
    /// token refresh (§4.7). Returns the raw successful response.
    pub(crate) async fn send(&self, req: Request) -> Result<RawResponse> {
        match self.send_with_retry(&req).await {
            Err(Error::Api(e)) if e.status == 401 && req.authenticated => {
                self.refresh().await?;
                self.send_with_retry(&req).await
            }
            other => other,
        }
    }

    /// Execute and decode JSON.
    pub(crate) async fn send_json<T: DeserializeOwned>(&self, req: Request) -> Result<T> {
        self.send(req).await?.json()
    }

    async fn send_with_retry(&self, req: &Request) -> Result<RawResponse> {
        let mut attempt = 0usize;
        loop {
            let tokens = if req.authenticated {
                Some(self.inner.tokens.read().await.clone())
            } else {
                None
            };
            let result = self.execute_once(req, tokens.as_ref()).await;
            let wait = match &result {
                Err(Error::Api(e)) if e.status == 429 || e.status == 503 => {
                    let base = e
                        .details
                        .as_ref()
                        .and_then(|d| d.get("__retry_after"))
                        .and_then(Value::as_u64)
                        .map(Duration::from_secs)
                        .unwrap_or(limits::RETRY_AFTER_DEFAULT);
                    Some(base + jitter(Duration::from_secs(limits::BACKOFF_JITTER_SECS)))
                }
                Err(Error::Network(_)) => Some(Duration::from_secs(1) * (attempt as u32 + 1)),
                _ => None,
            };
            match wait {
                Some(w) if attempt < limits::TRANSPORT_RETRIES => {
                    let w = w.min(limits::RETRY_WAIT_CAP);
                    debug!(path = %req.path, ?w, attempt, "retrying API request");
                    tokio::time::sleep(w).await;
                    attempt += 1;
                }
                _ => return result,
            }
        }
    }

    async fn execute_once(
        &self,
        req: &Request,
        tokens: Option<&SessionTokens>,
    ) -> Result<RawResponse> {
        let url = format!(
            "{}{}",
            self.inner.cfg.api_base_url.trim_end_matches('/'),
            req.path
        );
        let mut rb = self
            .inner
            .http
            .request(req.method.clone(), &url)
            .header("x-pm-appversion", self.inner.cfg.app_version_header())
            .header("User-Agent", self.user_agent().await);
        if !req.query.is_empty() {
            rb = rb.query(&req.query);
        }
        if let Some(t) = tokens {
            if !t.uid.is_empty() {
                rb = rb.header("x-pm-uid", &t.uid);
            }
            if !t.access_token.is_empty() {
                rb = rb.header("Authorization", format!("Bearer {}", t.access_token));
            }
        }
        for (k, v) in &req.headers {
            rb = rb.header(k, v);
        }
        rb = match &req.body {
            Body::None => rb,
            Body::Json(v) => rb.json(v),
            Body::Multipart(parts) => {
                let mut form = reqwest::multipart::Form::new();
                for p in parts {
                    let mut part = reqwest::multipart::Part::bytes(p.data.clone());
                    if let Some(f) = &p.filename {
                        part = part.file_name(f.clone());
                    }
                    if let Some(ct) = &p.content_type {
                        part = part
                            .mime_str(ct)
                            .map_err(|e| Error::Invalid(format!("content type: {e}")))?;
                    }
                    form = form.part(p.name.clone(), part);
                }
                rb.multipart(form)
            }
        };

        let resp = match rb.send().await {
            Ok(r) => r,
            Err(e) => {
                self.set_connected(false);
                return Err(Error::Network(e.to_string()));
            }
        };
        self.set_connected(true);
        let status = resp.status();
        if let Some(date) = resp
            .headers()
            .get(reqwest::header::DATE)
            .and_then(|d| d.to_str().ok())
            .and_then(|d| httpdate::parse_http_date(d).ok())
            && let Ok(server) = date.duration_since(std::time::UNIX_EPOCH)
        {
            let offset = server.as_secs() as i64 - crate::util::now_unix();
            self.inner.clock_offset.store(offset, Ordering::Relaxed);
        }
        let retry_after = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());
        let body = match resp.bytes().await {
            Ok(b) => b.to_vec(),
            Err(e) => {
                self.set_connected(false);
                return Err(Error::Network(e.to_string()));
            }
        };

        if status.as_u16() >= 400 {
            return Err(Error::Api(decode_api_error(status, &body, retry_after)));
        }
        Ok(RawResponse { body })
    }

    /// Perform a token refresh (§5.5.1, §4.7).
    pub async fn refresh(&self) -> Result<()> {
        let _guard = self.inner.refresh_lock.lock().await;
        let current = self.tokens().await;
        if current.uid.is_empty() || current.refresh_token.is_empty() {
            return Err(Error::Deauthenticated);
        }
        let mut body = serde_json::json!({
            "UID": current.uid,
            "RefreshToken": current.refresh_token,
            "ResponseType": "token",
            "GrantType": "refresh_token",
            "RedirectURI": self.inner.cfg.refresh_redirect_uri,
            "State": b64(random_bytes(32)),
        });
        if !current.access_token.is_empty() {
            body["AccessToken"] = Value::String(current.access_token.clone());
        }
        let req = Request::post("/auth/v4/refresh")
            .unauthenticated()
            .json(body);
        match self.send_with_retry(&req).await {
            Ok(raw) => {
                let r: super::auth::AuthResponse = raw.json()?;
                let tokens = SessionTokens {
                    uid: if r.uid.is_empty() { current.uid } else { r.uid },
                    access_token: r.access_token,
                    refresh_token: r.refresh_token,
                };
                *self.inner.tokens.write().await = tokens.clone();
                if let Some(l) = self.inner.token_listener.read().await.clone() {
                    l(&tokens);
                }
                Ok(())
            }
            Err(Error::Api(e)) if e.status == 400 || e.status == 422 || e.code == 10013 => {
                self.fire_deauth().await;
                Err(Error::Api(e))
            }
            Err(e) => {
                warn!("token refresh failed transiently: {e}");
                Err(e)
            }
        }
    }

    async fn fire_deauth(&self) {
        if !self.inner.deauth_fired.swap(true, Ordering::SeqCst)
            && let Some(l) = self.inner.deauth_listener.read().await.clone()
        {
            l();
        }
    }

    /// Attach the stored human-verification headers to a request, if any.
    pub(crate) async fn with_hv(&self, mut req: Request) -> Request {
        if let Some(hv) = self.inner.hv.read().await.clone() {
            req = req
                .header("x-pm-human-verification-token", hv.token)
                .header("x-pm-human-verification-token-type", hv.methods.join(","));
        }
        req
    }
}

fn decode_api_error(status: StatusCode, body: &[u8], retry_after: Option<u64>) -> ApiError {
    #[derive(serde::Deserialize)]
    struct Raw {
        #[serde(rename = "Code")]
        code: i64,
        #[serde(rename = "Error", default)]
        error: String,
        #[serde(rename = "Details", default)]
        details: Option<Value>,
    }
    let mut err = match serde_json::from_slice::<Raw>(body) {
        Ok(r) => ApiError {
            status: status.as_u16(),
            code: r.code,
            message: r.error,
            details: r.details,
        },
        Err(_) => ApiError {
            status: status.as_u16(),
            code: 0,
            message: status.canonical_reason().unwrap_or("unknown").to_string(),
            details: None,
        },
    };
    if let Some(ra) = retry_after {
        // Carried internally so that the retry loop can honour Retry-After.
        let mut d = match err.details.take() {
            Some(Value::Object(m)) => m,
            Some(other) => {
                let mut m = serde_json::Map::new();
                m.insert("__original".into(), other);
                m
            }
            None => serde_json::Map::new(),
        };
        d.insert("__retry_after".into(), Value::from(ra));
        err.details = Some(Value::Object(d));
    }
    err
}

/// `A (B)` → `A-B` folding for the client version (§4.2).
fn fold_version(v: &str) -> String {
    let v = v.trim();
    if let Some((a, rest)) = v.split_once(" (") {
        let b = rest.trim_end_matches(')');
        format!("{}-{}", a.trim(), b.trim()).replace(' ', "-")
    } else {
        v.replace(' ', "-")
    }
}

fn os_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "Darwin"
    } else if cfg!(target_os = "windows") {
        "Windows"
    } else {
        "Linux"
    }
}

/// Generic `{"Code": 1000|1001, ...}` envelope check.
pub(crate) fn check_code(v: &Value) -> Result<()> {
    match v.get("Code").and_then(Value::as_i64) {
        None | Some(1000) | Some(1001) => Ok(()),
        Some(code) => Err(Error::Api(ApiError {
            status: 200,
            code,
            message: v
                .get("Error")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            details: v.get("Details").cloned(),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fold() {
        assert_eq!(fold_version("1.2 (34)"), "1.2-34");
        assert_eq!(fold_version("115.0"), "115.0");
    }

    #[test]
    fn decode_error() {
        let e = decode_api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            br#"{"Code":2001,"Error":"bad"}"#,
            None,
        );
        assert_eq!(e.code, 2001);
        let e = decode_api_error(StatusCode::BAD_GATEWAY, b"<html>", None);
        assert_eq!(e.code, 0);
        assert_eq!(e.message, "Bad Gateway");
    }
}
