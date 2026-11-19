pub mod anchor;
pub mod audit;
pub mod keyring;
pub mod policy;
pub mod sandbox;
pub mod store;
pub mod tools;

use std::io;

#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    #[error("path is outside the sandbox: {path}")]
    PathOutsideSandbox { path: String },

    #[error("invalid path: {reason}")]
    InvalidPath { reason: String },

    #[error("file too large: {actual} bytes (max {max})")]
    FileTooLarge { actual: usize, max: usize },

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("audit log corrupted at seq {sequence_no}: {reason}")]
    AuditCorrupted { sequence_no: u64, reason: String },

    #[error("audit error: {0}")]
    Audit(String),

    #[error("keyring error: {0}")]
    Keyring(String),

    #[error("bridge error: {0}")]
    Bridge(String),

    /// El sidecar respondió con un objeto de error JSON-RPC. `code` y `data`
    /// se conservan para que la CLI pueda dar instrucciones concretas
    /// (ver `bridge::rpc_codes`).
    #[error("sidecar error {code}: {message}")]
    SidecarRpc {
        code: i64,
        message: String,
        data: Option<serde_json::Value>,
    },
}

pub type KernelResult<T> = Result<T, KernelError>;
