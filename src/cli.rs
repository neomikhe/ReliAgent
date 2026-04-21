use clap::{Parser, Subcommand};
use serde::Serialize;
use std::path::{Path, PathBuf};

use crate::kernel::audit::AuditStatus;
use crate::kernel::keyring;
use crate::kernel::sandbox::Sandbox;
use crate::kernel::store::AuditStore;
use crate::kernel::{KernelError, tools};

#[derive(Parser)]
#[command(
    name = "reli",
    version,
    about = "ReliAgent Trust Kernel (v0.0.3 — write_file + path_jail + SQLite audit + anchor)"
)]
struct Cli {
    /// Ruta raíz del sandbox. Por defecto: ~/ReliAgent_Sandbox
    #[arg(long, global = true)]
    sandbox: Option<PathBuf>,

    /// Directorio donde vive el audit.db y los anchor.log. Por defecto: ~/.reliagent
    #[arg(long, global = true)]
    audit_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Escribe un archivo dentro del sandbox y registra la acción en el log firmado
    Write {
        /// Ruta relativa al sandbox
        path: String,
        /// Contenido a escribir
        content: String,
    },
    /// Muestra la ruta del sandbox resuelta
    SandboxPath,
    /// Verifica la integridad del audit log persistente (SQLite + anchor.log).
    Verify,
}

#[derive(Serialize)]
struct WriteFileArgs<'a> {
    path: &'a str,
    bytes: usize,
}

fn default_home() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default())
}

fn default_sandbox_path() -> PathBuf {
    default_home().join("ReliAgent_Sandbox")
}

fn default_audit_dir() -> PathBuf {
    default_home().join(".reliagent")
}

fn load_audit_store(audit_dir: &Path) -> Result<AuditStore, i32> {
    let (key, created) = match keyring::load_or_create_audit_key() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[reli] error al acceder al keyring: {e}");
            return Err(3);
        }
    };
    if created {
        eprintln!(
            "[reli] nueva clave HMAC generada y guardada en keyring ({})",
            keyring::account_label()
        );
    }
    let db_path = audit_dir.join("audit.db");
    let anchor_dir = audit_dir.join("anchors");
    AuditStore::open(&db_path, &anchor_dir, key).map_err(|e| {
        eprintln!("[reli] error inicializando audit store: {e}");
        3
    })
}

pub fn run() -> i32 {
    let cli = Cli::parse();
    let sandbox_path = cli.sandbox.unwrap_or_else(default_sandbox_path);
    let audit_dir = cli.audit_dir.unwrap_or_else(default_audit_dir);

    match cli.command {
        Command::SandboxPath => {
            println!("{}", sandbox_path.display());
            0
        }
        Command::Write { path, content } => run_write(&sandbox_path, &audit_dir, &path, &content),
        Command::Verify => run_verify(&audit_dir),
    }
}

fn run_write(sandbox_path: &Path, audit_dir: &Path, path: &str, content: &str) -> i32 {
    let mut store = match load_audit_store(audit_dir) {
        Ok(s) => s,
        Err(code) => return code,
    };

    let sandbox = match Sandbox::open(sandbox_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[reli] error al abrir el sandbox: {e}");
            return 2;
        }
    };

    let args = WriteFileArgs {
        path,
        bytes: content.len(),
    };
    let result = tools::write_file(&sandbox, path, content.as_bytes());
    let status = match &result {
        Ok(()) => AuditStatus::Ok,
        Err(e) => AuditStatus::Rejected {
            reason: format!("{e}"),
        },
    };

    let record_hmac = match store.record("write_file", &args, status) {
        Ok(signed) => signed.hmac,
        Err(e) => {
            eprintln!("[reli] error registrando en el audit store: {e}");
            return 3;
        }
    };

    if let Err(e) = store.verify() {
        eprintln!("[reli] audit store corrupto tras registrar: {e}");
        return 3;
    }

    match result {
        Ok(()) => {
            println!(
                "[reli] ok: {} bytes escritos en {}",
                content.len(),
                sandbox.root_path().join(path).display()
            );
            println!("[reli] audit hmac: {record_hmac}");
            0
        }
        Err(e) => {
            eprintln!("[reli] rechazado: {e}");
            eprintln!("[reli] audit hmac: {record_hmac}");
            match e {
                KernelError::PathOutsideSandbox { .. }
                | KernelError::InvalidPath { .. }
                | KernelError::FileTooLarge { .. } => 1,
                _ => 2,
            }
        }
    }
}

fn run_verify(audit_dir: &Path) -> i32 {
    let store = match load_audit_store(audit_dir) {
        Ok(s) => s,
        Err(code) => return code,
    };
    match store.verify() {
        Ok(()) => {
            println!(
                "[reli] verify ok: {} entradas, hmac final {}",
                store.len(),
                store.last_hmac().unwrap_or("-")
            );
            println!("[reli] db: {}", store.db_path().display());
            0
        }
        Err(e) => {
            eprintln!("[reli] verify falló: {e}");
            3
        }
    }
}
