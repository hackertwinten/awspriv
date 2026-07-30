//! awspriv library — all modules live here so integration tests (and the thin
//! `main.rs` binary) can reach the assessment pipeline and scoring logic.

pub mod catalog;
pub mod cli;
pub mod counter;
pub mod creds;
pub mod enumerate;
pub mod error;
pub mod iam_read;
pub mod identity;
pub mod policy;
pub mod probe;
pub mod report;
pub mod score;
pub mod simulate;
