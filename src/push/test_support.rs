//! Test helpers: a minimal HTTP/1.1 stub of the Service.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::api::ApiClient;
use crate::config::DeploymentConfig;

/// One recorded request.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub body: serde_json::Value,
}

pub type Responder = Arc<dyn Fn(&Seen) -> (u16, String) + Send + Sync>;

pub struct Stub {
    pub base: String,
    pub seen: Arc<Mutex<Vec<Seen>>>,
}

pub fn config(base: &str) -> Arc<DeploymentConfig> {
    Arc::new(DeploymentConfig {
        api_base_url: base.into(),
        modulus_signing_key: String::new(),
        srp_salt_suffix: *b"suffix",
        refresh_redirect_uri: "https://example/".into(),
        app_product_token: "mail".into(),
        app_version: "1.0.0".into(),
        app_platform: Some("android".into()),
        product_name: "Test".into(),
        api_tls_pins: Vec::new(),
    })
}

pub async fn client(base: &str) -> ApiClient {
    let c = ApiClient::new(config(base)).unwrap();
    c.set_tokens(crate::api::SessionTokens {
        uid: "uid-1".into(),
        access_token: "at".into(),
        refresh_token: "rt".into(),
    })
    .await;
    c
}

/// Start a stub answering every request with `respond`.
pub async fn start(respond: Responder) -> Stub {
    start_with_delay(respond, std::time::Duration::ZERO).await
}

/// Like [`start`], waiting `delay` (asynchronously) before each response.
pub async fn start_with_delay(respond: Responder, delay: std::time::Duration) -> Stub {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let respond = respond.clone();
            let seen = seen2.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n");
                    if let Some(end) = header_end {
                        let head = String::from_utf8_lossy(&buf[..end]).to_string();
                        let len = head
                            .lines()
                            .find_map(|l| {
                                let (k, v) = l.split_once(':')?;
                                k.eq_ignore_ascii_case("content-length")
                                    .then(|| v.trim().parse::<usize>().ok())?
                            })
                            .unwrap_or(0);
                        if buf.len() >= end + 4 + len {
                            let mut first = head.lines().next().unwrap_or("").split(' ');
                            let method = first.next().unwrap_or("").to_string();
                            let path = first.next().unwrap_or("").to_string();
                            let body = serde_json::from_slice(&buf[end + 4..end + 4 + len])
                                .unwrap_or(serde_json::Value::Null);
                            let s = Seen { method, path, body };
                            let (status, resp) = respond(&s);
                            seen.lock().unwrap().push(s);
                            tokio::time::sleep(delay).await;
                            let out = format!(
                                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp}",
                                resp.len()
                            );
                            let _ = sock.write_all(out.as_bytes()).await;
                            return;
                        }
                    }
                    match sock.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                }
            });
        }
    });
    Stub { base, seen }
}

/// A [`crate::account::StateStore`] in memory.
#[derive(Default)]
pub struct MemStateStore {
    accounts: Mutex<Vec<crate::account::PersistedAccount>>,
}

impl crate::account::StateStore for MemStateStore {
    fn load_all(&self) -> crate::Result<Vec<crate::account::PersistedAccount>> {
        Ok(self.accounts.lock().unwrap().clone())
    }
    fn save(&self, a: &crate::account::PersistedAccount) -> crate::Result<()> {
        let mut v = self.accounts.lock().unwrap();
        v.retain(|x| x.user_id != a.user_id);
        v.push(a.clone());
        Ok(())
    }
    fn delete(&self, user_id: &str) -> crate::Result<()> {
        self.accounts
            .lock()
            .unwrap()
            .retain(|x| x.user_id != user_id);
        Ok(())
    }
    fn load_archive(&self) -> crate::Result<crate::account::PasswordArchive> {
        Ok(Default::default())
    }
    fn save_archive(&self, _: &crate::account::PasswordArchive) -> crate::Result<()> {
        Ok(())
    }
}

/// A signed-in account context with system mailboxes and one Inbox message
/// `m1`, talking to `base`.
pub async fn account(base: &str) -> Arc<crate::gateway::AccountContext> {
    use crate::api::types::{Address, Label, label_type};
    let store: Arc<dyn crate::account::StateStore> = Arc::new(MemStateStore::default());
    let gw = crate::account::GatewayPassword::generate();
    let mut p = crate::account::PersistedAccount::new("user-1", "u", "u@x.org", &gw);
    p.session_uid = "uid-1".into();
    p.refresh_token = "rt".into();
    store.save(&p).unwrap();
    let ctx = crate::gateway::AccountContext::new(
        client(base).await,
        Arc::new(Default::default()),
        Arc::new(Default::default()),
        store,
        p,
        Default::default(),
        vec![Address {
            id: "a1".into(),
            email: "u@x.org".into(),
            status: 1,
            ..Default::default()
        }],
        Default::default(),
    );
    ctx.set_labels(
        ["0", "3", "5", "6"]
            .iter()
            .map(|id| Label {
                id: (*id).into(),
                name: (*id).into(),
                path: (*id).into(),
                kind: label_type::SYSTEM,
                ..Default::default()
            })
            .collect(),
    );
    ctx.rebuild_imap_sets().unwrap();
    let set = ctx.imap_set_for_message("a1").unwrap();
    let mut m = crate::imap::store::LocalMessage::new("m1");
    m.label_ids = vec!["0".into(), "5".into()];
    m.address_id = "a1".into();
    set.write()
        .unwrap()
        .upsert_message(m, &["0".to_string(), "5".to_string()])
        .unwrap();
    ctx
}
