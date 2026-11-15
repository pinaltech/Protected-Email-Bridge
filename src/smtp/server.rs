//! SMTP submission server (§13.1–§13.4, §13.14).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, warn};

use super::pipeline::{Submission, SubmitError, submit};
use crate::config::{ListenerSecurity, limits};
use crate::error::Result;
use crate::gateway::AccountContext;
use crate::util::b64_decode;

/// Resolves SMTP credentials to an account and address ID (§13.4).
pub trait SmtpAuthenticator: Send + Sync + 'static {
    fn authenticate(&self, username: &str, password: &str)
    -> Option<(Arc<AccountContext>, String)>;
}

/// SMTP server configuration. `tls` should be built once with
/// [`TlsIdentity::acceptor`](crate::tls::TlsIdentity::acceptor) and shared
/// with the IMAP listener (§11.1, §13.1).
#[derive(Clone)]
pub struct SmtpServer {
    pub auth: Arc<dyn SmtpAuthenticator>,
    pub tls: TlsAcceptor,
    pub security: ListenerSecurity,
}

impl SmtpServer {
    /// Bind on 127.0.0.1:`port` and serve forever.
    pub async fn serve(self, port: u16) -> Result<()> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).await?;
        loop {
            let (sock, peer) = listener.accept().await?;
            let me = self.clone();
            tokio::spawn(async move {
                if let Err(e) = me.handle(sock).await {
                    debug!(%peer, "SMTP session ended: {e}");
                }
            });
        }
    }

    async fn handle(&self, sock: TcpStream) -> Result<()> {
        match self.security {
            ListenerSecurity::ImplicitTls => {
                let tls = self.tls.accept(sock).await?;
                let mut s = Session::new(self.auth.clone(), true);
                s.greet = true;
                s.run(tls).await.map(|_| ())
            }
            ListenerSecurity::StartTls => {
                let mut s = Session::new(self.auth.clone(), false);
                s.greet = true;
                if let Some(plain) = s.run(sock).await? {
                    let tls = match self.tls.accept(plain).await {
                        Ok(t) => t,
                        Err(e) => {
                            warn!("STARTTLS handshake failed: {e}");
                            return Ok(());
                        }
                    };
                    let mut s2 = Session::new(self.auth.clone(), true);
                    s2.greet = false;
                    s2.run(tls).await?;
                }
                Ok(())
            }
        }
    }
}

struct Session {
    auth: Arc<dyn SmtpAuthenticator>,
    is_tls: bool,
    greet: bool,
    helo: Option<String>,
    account: Option<(Arc<AccountContext>, String)>,
    reverse_path: Option<String>,
    recipients: Vec<String>,
    bdat: Vec<u8>,
    errors: u32,
}

enum Flow {
    Continue,
    Quit,
    StartTls,
}

impl Session {
    fn new(auth: Arc<dyn SmtpAuthenticator>, is_tls: bool) -> Self {
        Self {
            auth,
            is_tls,
            greet: true,
            helo: None,
            account: None,
            reverse_path: None,
            recipients: Vec::new(),
            bdat: Vec::new(),
            errors: 0,
        }
    }

    fn reset(&mut self) {
        self.reverse_path = None;
        self.recipients.clear();
        self.bdat.clear();
    }

    /// Run until QUIT/EOF. Returns the stream back if STARTTLS was accepted.
    async fn run<S: AsyncRead + AsyncWrite + Unpin>(&mut self, stream: S) -> Result<Option<S>> {
        let mut r = BufReader::new(stream);
        if self.greet {
            write(&mut r, "220 127.0.0.1 ESMTP Service Ready").await?;
        }
        loop {
            let Some(line) = read_line(&mut r).await? else {
                return Ok(None);
            };
            match self.command(&mut r, &line).await? {
                Flow::Continue => {}
                Flow::Quit => return Ok(None),
                Flow::StartTls => return Ok(Some(r.into_inner())),
            }
            if self.errors > limits::SMTP_MAX_SYNTAX_ERRORS {
                write(&mut r, "500 5.5.1 Too many errors. Quiting now").await?;
                return Ok(None);
            }
        }
    }

    async fn syntax_error<S: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        r: &mut BufReader<S>,
        reply: &str,
    ) -> Result<Flow> {
        self.errors += 1;
        write(r, reply).await?;
        Ok(Flow::Continue)
    }

    async fn command<S: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        r: &mut BufReader<S>,
        line: &str,
    ) -> Result<Flow> {
        let (verb, arg) = match line.split_once(' ') {
            Some((v, a)) => (v.to_ascii_uppercase(), a.trim().to_string()),
            None => (line.trim().to_ascii_uppercase(), String::new()),
        };
        match verb.as_str() {
            "EHLO" | "HELO" => {
                if arg.is_empty() {
                    return self.syntax_error(r, "501 5.5.2 Missing domain").await;
                }
                self.helo = Some(arg.clone());
                self.reset();
                if verb == "HELO" {
                    write(r, &format!("250 2.0.0 Hello {arg}")).await?;
                } else {
                    let mut lines = vec![
                        format!("250-Hello {arg}"),
                        "250-PIPELINING".into(),
                        "250-8BITMIME".into(),
                        "250-ENHANCEDSTATUSCODES".into(),
                        "250-CHUNKING".into(),
                    ];
                    if !self.is_tls {
                        lines.push("250-STARTTLS".into());
                    }
                    lines.push("250-AUTH PLAIN LOGIN".into());
                    lines.push("250 SIZE".into());
                    write(r, &lines.join("\r\n")).await?;
                }
            }
            "STARTTLS" => {
                if self.is_tls {
                    write(r, "502 5.5.1 Already running in TLS").await?;
                } else {
                    write(r, "220 2.0.0 Ready to start TLS").await?;
                    return Ok(Flow::StartTls);
                }
            }
            "AUTH" => return self.auth_cmd(r, &arg).await,
            "MAIL" => {
                if self.helo.is_none() {
                    write(r, "502 5.5.1 Please introduce yourself first.").await?;
                    return Ok(Flow::Continue);
                }
                let Some(rest) = strip_prefix_ci(&arg, "FROM:") else {
                    return self.syntax_error(r, "501 5.5.4 Invalid syntax").await;
                };
                let (addr, params) = parse_path(rest);
                for p in params {
                    let up = p.to_ascii_uppercase();
                    if up == "SMTPUTF8" || up == "REQUIRETLS" || up == "BODY=BINARYMIME" {
                        write(r, "504 5.5.4 Not implemented").await?;
                        return Ok(Flow::Continue);
                    }
                    let ok = up.starts_with("SIZE=")
                        || up == "BODY=7BIT"
                        || up == "BODY=8BITMIME"
                        || up.starts_with("AUTH=");
                    if !ok {
                        write(r, "504 5.5.4 Unknown parameter").await?;
                        return Ok(Flow::Continue);
                    }
                }
                self.reverse_path = Some(addr.clone());
                write(r, &format!("250 2.0.0 Roger, accepting mail from <{addr}>")).await?;
            }
            "RCPT" => {
                if self.reverse_path.is_none() {
                    write(r, "502 5.5.1 Missing MAIL FROM command.").await?;
                    return Ok(Flow::Continue);
                }
                let Some(rest) = strip_prefix_ci(&arg, "TO:") else {
                    return self.syntax_error(r, "501 5.5.4 Invalid syntax").await;
                };
                let (addr, _) = parse_path(rest);
                if !addr.is_empty() {
                    self.recipients.push(addr.clone());
                }
                write(r, &format!("250 2.0.0 I'll make sure <{addr}> gets this")).await?;
            }
            "DATA" => {
                if self.reverse_path.is_none() {
                    write(r, "502 5.5.1 Missing RCPT TO command.").await?;
                    return Ok(Flow::Continue);
                }
                write(
                    r,
                    "354 2.0.0 Go ahead. End your data with <CR><LF>.<CR><LF>",
                )
                .await?;
                let data = read_data(r).await?;
                self.deliver(r, data).await?;
            }
            "BDAT" => {
                let mut parts = arg.split_whitespace();
                let Some(n) = parts.next().and_then(|n| n.parse::<usize>().ok()) else {
                    return self.syntax_error(r, "501 5.5.4 Invalid BDAT size").await;
                };
                let last = parts.next().is_some_and(|p| p.eq_ignore_ascii_case("LAST"));
                let mut buf = vec![0u8; n];
                r.read_exact(&mut buf).await?;
                self.bdat.extend_from_slice(&buf);
                if last {
                    let data = std::mem::take(&mut self.bdat);
                    self.deliver(r, data).await?;
                } else {
                    write(r, "250 2.0.0 Continue").await?;
                }
            }
            "RSET" => {
                self.reset();
                write(r, "250 2.0.0 Session reset").await?;
            }
            "NOOP" => write(r, "250 2.0.0 I have sucessfully done nothing").await?,
            "VRFY" => write(r, "252 2.5.0 Cannot VRFY user, but will accept message").await?,
            "QUIT" => {
                write(r, "221 2.0.0 Bye").await?;
                return Ok(Flow::Quit);
            }
            "SEND" | "SOML" | "SAML" | "EXPN" | "HELP" | "TURN" => {
                write(r, &format!("502 5.5.1 {verb} command not implemented")).await?;
            }
            _ => {
                return self
                    .syntax_error(r, "500 5.5.2 Syntax error, command unrecognized")
                    .await;
            }
        }
        Ok(Flow::Continue)
    }

    async fn deliver<S: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        r: &mut BufReader<S>,
        data: Vec<u8>,
    ) -> Result<()> {
        let sub = Submission {
            reverse_path: self.reverse_path.clone().unwrap_or_default(),
            recipients: self.recipients.clone(),
            data,
        };
        let (ctx, addr_id) = match &self.account {
            Some((c, a)) => (Some(c.clone()), a.clone()),
            None => (None, String::new()),
        };
        let res: std::result::Result<String, SubmitError> =
            submit(ctx.as_ref(), &addr_id, sub).await;
        self.reset();
        match res {
            Ok(_) => write(r, "250 2.0.0 OK: queued").await,
            Err(e) => write(r, &e.smtp_reply()).await,
        }
    }

    async fn auth_cmd<S: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        r: &mut BufReader<S>,
        arg: &str,
    ) -> Result<Flow> {
        if self.helo.is_none() {
            write(r, "502 5.5.1 Please introduce yourself first.").await?;
            return Ok(Flow::Continue);
        }
        if self.account.is_some() {
            write(r, "503 5.5.1 Already authenticated").await?;
            return Ok(Flow::Continue);
        }
        let mut it = arg.split_whitespace();
        let mech = it.next().unwrap_or_default().to_ascii_uppercase();
        let initial = it.next().map(str::to_string);
        let creds = match mech.as_str() {
            "PLAIN" => {
                let resp = match initial {
                    Some(i) => i,
                    None => {
                        write(r, "334 ").await?;
                        match read_line(r).await? {
                            Some(l) => l,
                            None => return Ok(Flow::Quit),
                        }
                    }
                };
                if resp.trim() == "*" {
                    write(r, "501 5.0.0 Negotiation cancelled").await?;
                    return Ok(Flow::Continue);
                }
                let Ok(raw) = b64_decode(resp.trim()) else {
                    write(r, "454 4.7.0 Invalid base64 data").await?;
                    return Ok(Flow::Continue);
                };
                let parts: Vec<&[u8]> = raw.split(|b| *b == 0).collect();
                if parts.len() != 3 {
                    write(r, "454 4.7.0 Invalid credentials format").await?;
                    return Ok(Flow::Continue);
                }
                let authz = String::from_utf8_lossy(parts[0]).to_string();
                let user = String::from_utf8_lossy(parts[1]).to_string();
                let pass = String::from_utf8_lossy(parts[2]).to_string();
                if !authz.is_empty() && authz != user {
                    write(r, "454 4.7.0 Identities not supported").await?;
                    return Ok(Flow::Continue);
                }
                (user, pass)
            }
            "LOGIN" => {
                let mut vals = Vec::new();
                let mut pending = initial;
                for prompt in ["334 VXNlcm5hbWU6", "334 UGFzc3dvcmQ6"] {
                    let line = match pending.take() {
                        Some(l) => l,
                        None => {
                            write(r, prompt).await?;
                            match read_line(r).await? {
                                Some(l) => l,
                                None => return Ok(Flow::Quit),
                            }
                        }
                    };
                    if line.trim() == "*" {
                        write(r, "501 5.0.0 Negotiation cancelled").await?;
                        return Ok(Flow::Continue);
                    }
                    match b64_decode(line.trim()) {
                        Ok(v) => vals.push(String::from_utf8_lossy(&v).to_string()),
                        Err(_) => {
                            write(r, "454 4.7.0 Invalid base64 data").await?;
                            return Ok(Flow::Continue);
                        }
                    }
                }
                (vals[0].clone(), vals[1].clone())
            }
            _ => {
                write(r, "504 5.7.4 Unrecognized authentication type").await?;
                return Ok(Flow::Continue);
            }
        };
        match self.auth.authenticate(&creds.0, &creds.1) {
            Some((ctx, addr)) => {
                ctx.client.note_smtp_auth().await;
                self.account = Some((ctx, addr));
                write(r, "235 2.0.0 Authentication succeeded").await?;
            }
            None => write(r, "454 4.7.0 invalid username or password").await?,
        }
        Ok(Flow::Continue)
    }
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    (s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix))
        .then(|| s[prefix.len()..].trim())
}

/// Parse `<addr> PARAM PARAM` (angle brackets optional).
fn parse_path(s: &str) -> (String, Vec<String>) {
    let s = s.trim();
    let (addr, rest) = if let Some(stripped) = s.strip_prefix('<') {
        match stripped.find('>') {
            Some(i) => (stripped[..i].to_string(), &stripped[i + 1..]),
            None => (stripped.to_string(), ""),
        }
    } else {
        match s.split_once(' ') {
            Some((a, r)) => (a.to_string(), r),
            None => (s.to_string(), ""),
        }
    };
    (
        addr.trim().to_string(),
        rest.split_whitespace().map(str::to_string).collect(),
    )
}

async fn write<S: AsyncRead + AsyncWrite + Unpin>(r: &mut BufReader<S>, line: &str) -> Result<()> {
    let w = r.get_mut();
    w.write_all(line.as_bytes()).await?;
    w.write_all(b"\r\n").await?;
    w.flush().await?;
    Ok(())
}

async fn read_line<S: AsyncRead + Unpin>(r: &mut BufReader<S>) -> Result<Option<String>> {
    let mut buf = Vec::new();
    let n = (&mut *r)
        .take(limits::SMTP_MAX_LINE as u64)
        .read_until(b'\n', &mut buf)
        .await?;
    if n == 0 {
        return Ok(None);
    }
    while buf.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        buf.pop();
    }
    Ok(Some(String::from_utf8_lossy(&buf).to_string()))
}

/// Read DATA until `CRLF.CRLF`, undoing dot-stuffing. The terminator is
/// not included.
async fn read_data<S: AsyncRead + Unpin>(r: &mut BufReader<S>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut line = Vec::new();
        let n = r.read_until(b'\n', &mut line).await?;
        if n == 0 {
            break;
        }
        let trimmed: &[u8] = line
            .strip_suffix(b"\r\n")
            .or_else(|| line.strip_suffix(b"\n"))
            .unwrap_or(&line);
        if trimmed == b"." {
            break;
        }
        let content = if line.starts_with(b"..") {
            &line[1..]
        } else {
            &line[..]
        };
        out.extend_from_slice(content);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(parse_path("<a@b> SIZE=10 BODY=8BITMIME").0, "a@b");
        assert_eq!(parse_path("<a@b> SIZE=10").1, vec!["SIZE=10"]);
        assert_eq!(parse_path("<>").0, "");
        assert_eq!(strip_prefix_ci("from:<x>", "FROM:"), Some("<x>"));
    }

    #[tokio::test]
    async fn data_unstuffing() {
        let input: &[u8] = b"line1\r\n..dot\r\n.\r\nNEXT";
        let mut r = BufReader::new(input);
        let d = read_data(&mut r).await.unwrap();
        assert_eq!(d, b"line1\r\n.dot\r\n");
    }
}
