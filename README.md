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
| `push` | §14 | Mobile push-notification client profile: device key (Ed25519/Curve25519, unlocked, B64 in a `SecureStore`), device registration (`POST /core/v4/devices`, background `Registrar` with 9100 deferral and network retry), envelope decryption, `email`/`open_url` payloads and presentation, quick actions with a versioned durable queue (immediate bounded attempt, local apply/revert, deferred send), notification-originated message/conversation opening, and an Android cloud-messaging transport (`push::fcm`) built on [`fcm_receiver_rs`](https://github.com/agusibrahim/fcm_receiver.rs) |
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

// Push notifications (§14). Use the OS keychain for the SecureStore, and
// set `app_platform: Some("android".into())` in the DeploymentConfig.
use protected_email_bridge::push::{NotificationClient, fcm::FcmConfig};
let push = NotificationClient::new(gw.clone(), secure_store, None)?;
push.start_registration(None);
let _fcm = push.start_fcm(FcmConfig::new(api_key, app_id, project_id), presenter)?;
// Envelopes wait until stored accounts are resumed (instead of gw.resume_all()):
push.resume_accounts().await?;
// On user interaction:
push.quick_action(&user_id, QuickAction::MoveToArchive, &message_id, Some(remaining)).await?;
let opened = push.open_message(&user_id, &message_id).await?;

// IMAP: a protocol front-end calls `gw.imap_login(user, pass)` and then the
// returned `ImapBackend` methods for each command.
```

## Not included

* **IMAP wire protocol.** There is no IMAP command parser or response
  renderer (FETCH/BODYSTRUCTURE/SEARCH/IDLE framing). The mailbox model,
  local state, change notifications and command semantics are implemented in
  `imap::backend::ImapBackend`, ready to plug into a front-end.
* **Push provider details.** `fcm_receiver_rs` is blocking and its socket
  read cannot be interrupted, so `FcmPushProvider::stop` takes effect when
  the current connection ends. Only the Android cloud-messaging transport
  (environment 4) is built in; other environments are supported by feeding
  `NotificationClient::set_registration_record` and `run` yourself.
* **Push redelivery.** Processed deliveries are remembered as ciphertext
  hashes (28 days, at most 512) in the `SecureStore`, so messages the
  Push Provider redelivers after a restart are skipped. This needs a
  persistent `SecureStore`; the bundled `MemorySecureStore` is not.
* **Push local store.** Conversations and the "draft open in composer" set
  are kept in memory (`AccountContext::push`); messages are stored in the
  IMAP mailbox set without bodies, which are built on demand.
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
