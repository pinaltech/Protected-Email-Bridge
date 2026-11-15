# protected_email_bridge

A Rust library (edition 2024, `rust-version = "1.100"`) that implements the
*Local Encrypted-Mail Gateway* described in `SPECIFICATION.md`. It connects an
end-to-end encrypted mail Service's HTTPS/JSON API to standard mail clients.

## Modules

| Module | Spec | Contents |
|---|---|---|
| `api` | §4, §7, §8 | Transport (headers, retry/Retry-After, 401 → refresh, connectivity, clock sync), SPKI certificate pinning, back-off, every endpoint, data model |
| `srp`, `auth` | §5 | SRP-6a (password versions 0–4, modulus verification, parameter validation, constant-time arithmetic for `a`/`x`/`S`), TOTP/FIDO2, human verification, resume |
| `keys`, `crypto` | §6, §9 | Salted key passphrases, user/address key rings, decrypt/encrypt/sign, session keys, packet splitting, armor |
| `literal` | §11.8 | RFC 5322 literal synthesis, including PGP/MIME, decryption-failure and build-failure placeholders |
| `import` | §9.6 | Per-part and full PGP/MIME import encryption |
| `imap` | §11 | Mailbox model, modified UTF-7, UIDVALIDITY, local state with change notifications, admission control, command→API backend (STORE/COPY/MOVE/EXPUNGE/APPEND/CREATE/RENAME/DELETE/FETCH) |
| `sync` | §12 | Initial sync (resumable, batched, adaptive concurrency) and the event loop |
| `smtp` | §13 | SMTP server (STARTTLS/implicit TLS, AUTH PLAIN/LOGIN, DATA/BDAT), MIME normalisation, parent resolution, drafts, attachments, send preferences, packages, dedup, throttling, error mapping |
| `account`, `gateway` | §10 | Gateway passwords, address modes, AES-GCM-encrypted state store, account runtime, gateway façade |
| `tls` | §11.1 | Self-signed RSA-2048 listener certificate; shared listener TLS config (TLS 1.2 minimum, no client certificate request) |

## Usage sketch

```rust,ignore
use std::sync::Arc;
use protected_email_bridge::{account::EncryptedFileStore, auth, config::*, gateway::Gateway,
    smtp::SmtpServer, sync::Synchroniser, tls::TlsIdentity};

let cfg = DeploymentConfig { /* operator-provided constants (§3.1) */ };
let store = Arc::new(EncryptedFileStore::new("state", key_from_os_keychain)?);
let gw = Gateway::new(cfg, LocalArtifacts::default(), GatewaySettings::default(), store);

// Login (§5).
let client = gw.new_client()?;
let mut pending = auth::login(&client, "user@example.org", b"password", None,
                              |id| gw.is_connected_user(id)).await?;
if pending.needs_second_factor() { pending.submit_totp("123456").await?; }
let logged = pending.finish(None).await?;
let account = gw.add_login(client, "user@example.org", logged).await?;
println!("Gateway password: {}", account.gateway_password()?.display());

// Sync and events (§12).
Synchroniser::new(account.clone(), None).start();

// SMTP (§13).
let tls = TlsIdentity::generate()?.acceptor()?;
tokio::spawn(SmtpServer { auth: gw.clone(), tls, security: ListenerSecurity::StartTls }.serve(1025));

// IMAP: a protocol front-end calls `gw.imap_login(user, pass)` and then the
// returned `ImapBackend` methods for each command.
```

## Not included

* **IMAP wire protocol.** There is no IMAP command parser or response
  renderer (FETCH/BODYSTRUCTURE/SEARCH/IDLE framing). The mailbox model,
  local state, change notifications and command semantics are implemented in
  `imap::backend::ImapBackend`, ready to plug into a front-end.
* OpenPGP signatures use the local clock rather than the Service time (the
  offset is tracked in `ApiClient::server_now`).

## Testing

```
cargo test
```

The unit tests cover the protocol logic. `tests/crypto_roundtrip.rs` runs
real OpenPGP round-trips with generated Ed25519/Curve25519 keys. Nothing has
been run against a live Service, because that needs the deployment
constants.
