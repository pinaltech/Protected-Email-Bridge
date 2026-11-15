//! IMAP server model (§11): mailbox model, local state, admission control
//! and the command-to-API mapping backend.

pub mod admission;
pub mod backend;
pub mod mailbox;
pub mod store;
