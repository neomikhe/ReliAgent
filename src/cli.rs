use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::kernel::sandbox::Sandbox;
use crate::kernel::tools;

#[derive(Parser)]
#[command(
    name = "reli",
    version,
    about = "ReliAgent Trust Kernel (v0.0.1 — write_file + path_jail only)"
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
    /// Escribe un archivo dentro del sandbox
    Write {
        /// Ruta relativa al sandbox
        path: String,
        /// Contenido a escribir
        content: String,
    },
    /// Muestra la ruta del sandbox resuelta
    SandboxPath,
}

fn default_sandbox_path() -> PathBuf {
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    home.join("ReliAgent_Sandbox")
}

pub fn run() -> i32 {
    let cli = Cli::parse();
    let sandbox_path = cli.sandbox.unwrap_or_else(default_sandbox_path);

    match cli.command {
        Command::SandboxPath => {
            println!("{}", sandbox_path.display());
            0
        }
        Command::Write { path, content } => {
            let sandbox = match Sandbox::open(&sandbox_path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[reli] error al abrir el sandbox: {e}");
                    return 2;
                }
            };

            match tools::write_file(&sandbox, &path, content.as_bytes()) {
                Ok(()) => {
                    println!(
                        "[reli] ok: {} bytes escritos en {}",
                        content.len(),
                        sandbox.root_path().join(&path).display()
                    );
                    0
                }
                Err(e) => {
                    eprintln!("[reli] rechazado: {e}");
                    1
                }
            }
        }
    }
}
