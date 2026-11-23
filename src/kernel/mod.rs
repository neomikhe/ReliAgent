pub mod anchor;
pub mod audit;
pub mod head;
pub mod keyring;
pub mod policy;
pub mod sandbox;
pub mod store;
pub mod tools;

use std::io;
use std::path::Path;

/// Crea `dir` y los padres que falten, en Unix solo accesibles para el
/// usuario (0700): el log, los anchors y la copia de migración guardan las
/// rutas y las horas de lo que hizo el agente. Los directorios que ya
/// existían no se tocan. En Windows, los permisos heredados del perfil.
pub fn create_private_dir_all(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

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

    /// Otro proceso tiene el log bloqueado. No implica manipulación.
    #[error(
        "audit log is in use by another process (another reli, or a tool reading audit.db); \
         only one may use it at a time"
    )]
    AuditBusy,

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
