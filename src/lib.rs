//! Library entry point.
//!
//! The `reli` binary re-exports these modules internally via `main.rs`.
//! They are also exposed here so integration tests in `tests/` can link
//! against the kernel and bridge without going through the CLI.

pub mod approval;
pub mod bridge;
pub mod kernel;
