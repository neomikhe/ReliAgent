pub mod policy;
pub mod sandbox;
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
}

pub type KernelResult<T> = Result<T, KernelError>;
