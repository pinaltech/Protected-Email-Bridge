//! # protected_email_bridge
//!
//! A library implementation of the *Local Encrypted-Mail Gateway* functional
//! specification (`SPECIFICATION.md`). It bridges an end-to-end encrypted
//! mail Service (reached through its HTTPS/JSON API) to standard mail
//! clients:
//!
//! * [`api`] — the authenticated API client: transport, retries, token
//!   refresh, connectivity, every endpoint of §8 and the data model of §7.
//! * [`srp`] / [`auth`] — SRP-6a login, second factors, human verification,
//!   session lifecycle (§5).
//! * [`keys`] / [`crypto`] — key salts, salted passphrases, key ring
//!   unlocking and the OpenPGP lifecycle (§6, §9).
//! * [`literal`] — RFC 5322 literal synthesis from Service messages (§11.8).
//! * [`imap`] — the IMAP mailbox model, local state and command-to-API
//!   mapping (§11).
//! * [`sync`] — initial synchronisation and the event loop (§12).
//! * [`smtp`] — the SMTP submission server and pipeline (§13).
//! * [`account`] — gateway passwords, address modes and persisted state (§10).
//! * [`push`] — the mobile push-notification client profile (§14).

pub mod account;
pub mod api;
pub mod auth;
pub mod config;
pub mod crypto;
pub mod error;
pub mod fingerprint;
pub mod gateway;
pub mod imap;
pub mod import;
pub mod keys;
pub mod literal;
pub mod mime;
pub mod push;
pub mod smtp;
pub mod srp;
pub mod sync;
pub mod tls;
pub mod util;

pub use error::{Error, Result};
