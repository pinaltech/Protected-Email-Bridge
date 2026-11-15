//! SMTP submission (§13).

pub mod dedup;
pub mod package;
pub mod parse;
pub mod pipeline;
pub mod prefs;
pub mod server;

pub use pipeline::{Submission, SubmitError, submit};
pub use server::{SmtpAuthenticator, SmtpServer};
