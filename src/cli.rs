use clap::{Parser, Subcommand};
use serde::Serialize;
use std::path::{Path, PathBuf};

use crate::kernel::audit::{AuditLog, AuditStatus};
use crate::kernel::keyring;
use crate::kernel::sandbox::Sandbox;
use crate::kernel::{KernelError, tools};

#[derive(Parser)]
#[command(
    name = "reli",
    version,
    about = "ReliAgent Trust Kernel (v0.0.2 — write_file + path_jail + audit chain)"
)]
struct Cli {
    /// Ruta raíz del sandbox. Por defecto: ~/ReliAgent_Sandbox
    #[arg(long, global = true)]
    sandbox: Option<PathBuf>,

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
    /// Self-test de la cadena firmada: genera un log en memoria y valida integridad.
    /// Nota: v0.0.2 aún no persiste el log en disco.
    Verify,
}

#[derive(Serialize)]
struct WriteFileArgs<'a> {
    path: &'a str,
    bytes: usize,
}

fn default_sandbox_path() -> PathBuf {
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    home.join("ReliAgent_Sandbox")
}

fn load_audit_log() -> Result<AuditLog, i32> {
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
    AuditLog::with_key(key).map_err(|e| {
        eprintln!("[reli] error inicializando audit log: {e}");
        3
    })
}

pub fn run() -> i32 {
    let cli = Cli::parse();
    let sandbox_path = cli.sandbox.unwrap_or_else(default_sandbox_path);

    match cli.command {
        Command::SandboxPath => {
            println!("{}", sandbox_path.display());
            0
        }
        Command::Write { path, content } => run_write(&sandbox_path, &path, &content),
        Command::Verify => run_verify_selftest(),
    }
}

fn run_write(sandbox_path: &Path, path: &str, content: &str) -> i32 {
    let mut audit = match load_audit_log() {
        Ok(a) => a,
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

    let record_hmac = match audit.record("write_file", &args, status) {
        Ok(signed) => signed.hmac.clone(),
        Err(e) => {
            eprintln!("[reli] error registrando en el audit log: {e}");
            return 3;
        }
    };

    if let Err(e) = audit.verify() {
        eprintln!("[reli] audit log corrupto tras registrar: {e}");
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

fn run_verify_selftest() -> i32 {
    let mut audit = match load_audit_log() {
        Ok(a) => a,
        Err(code) => return code,
    };

    let sample: [(&str, WriteFileArgs, AuditStatus); 3] = [
        (
            "write_file",
            WriteFileArgs {
                path: "a.txt",
                bytes: 4,
            },
            AuditStatus::Ok,
        ),
        (
            "write_file",
            WriteFileArgs {
                path: "b.txt",
                bytes: 1,
            },
            AuditStatus::Ok,
        ),
        (
            "write_file",
            WriteFileArgs {
                path: "../escape",
                bytes: 0,
            },
            AuditStatus::Rejected {
                reason: "PathOutsideSandbox".into(),
            },
        ),
    ];
    for (tool, args, status) in sample {
        if let Err(e) = audit.record(tool, &args, status) {
            eprintln!("[reli] error construyendo self-test: {e}");
            return 3;
        }
    }

    match audit.verify() {
        Ok(()) => {
            println!(
                "[reli] verify ok: {} entradas, hmac final {}",
                audit.len(),
                audit.last_hmac().unwrap_or("-")
            );
            println!(
                "[reli] nota: v0.0.2 aún no persiste el log; este self-test vive solo en memoria."
            );
            0
        }
        Err(e) => {
            eprintln!("[reli] verify falló: {e}");
            3
        }
    }
}
