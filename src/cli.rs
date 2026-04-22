use clap::{Parser, Subcommand};
use serde::Serialize;
use std::path::{Path, PathBuf};

use reliagent::approval::{self, ApprovalDecision, ApprovalMode};
use reliagent::bridge::{AgentRunResult, Bridge, SidecarSpec};
use reliagent::kernel::audit::AuditStatus;
use reliagent::kernel::keyring;
use reliagent::kernel::sandbox::Sandbox;
use reliagent::kernel::store::AuditStore;
use reliagent::kernel::tools::{DirEntry, DirEntryKind};
use reliagent::kernel::{KernelError, tools};

/// Exit codes (documented contract — changing these breaks scripts).
/// 0 success
/// 1 policy/agent/user rejected
/// 2 malformed input / unsupported proposal
/// 3 audit or keyring failure
/// 4 bridge / sidecar failure
/// 5 approval timeout
const EXIT_OK: i32 = 0;
const EXIT_REJECTED: i32 = 1;
const EXIT_BAD_INPUT: i32 = 2;
const EXIT_AUDIT: i32 = 3;
const EXIT_BRIDGE: i32 = 4;
const EXIT_TIMEOUT: i32 = 5;

#[derive(Parser)]
#[command(
    name = "reli",
    version,
    about = "ReliAgent Trust Kernel (v0.1.0 Research Preview — kernel + audit + orquestador + aprobación TTY)"
)]
struct Cli {
    /// Ruta raíz del sandbox. Por defecto: ~/ReliAgent_Sandbox
    #[arg(long, global = true)]
    sandbox: Option<PathBuf>,

    /// Directorio donde vive el audit.db y los anchor.log. Por defecto: ~/.reliagent
    #[arg(long, global = true)]
    audit_dir: Option<PathBuf>,

    /// Intérprete Python para el sidecar. Por defecto: python
    #[arg(long, global = true)]
    python: Option<PathBuf>,

    /// Directorio de trabajo del sidecar Python. Por defecto: ./python-core
    #[arg(long, global = true)]
    python_cwd: Option<PathBuf>,

    /// No pedir confirmación por TTY — si el agente propone una acción,
    /// será rechazada automáticamente (modo seguro para scripts).
    #[arg(long, global = true)]
    non_interactive: bool,

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
    /// Lee un archivo dentro del sandbox. Imprime el contenido en stdout.
    Read {
        /// Ruta relativa al sandbox
        path: String,
    },
    /// Lista el contenido de un directorio dentro del sandbox.
    Ls {
        /// Ruta relativa (opcional). Por defecto lista la raíz del sandbox.
        path: Option<String>,
    },
    /// Comandos del sandbox.
    Sandbox {
        #[command(subcommand)]
        action: SandboxAction,
    },
    /// Verifica la integridad del audit log persistente (SQLite + anchor.log).
    Verify,
    /// Borra completamente el estado del kernel: audit.db, anchors, sandbox
    /// y la clave HMAC en el keyring. Requiere `--wipe-everything`.
    Reset {
        /// Confirmación obligatoria para ejecutar el reset.
        #[arg(long)]
        wipe_everything: bool,
        /// Saltar el prompt de confirmación "type WIPE".
        #[arg(long)]
        force: bool,
    },
    /// Corre el orquestador Python con un prompt y, si el crítico aprueba,
    /// pide confirmación por TTY y ejecuta la propuesta dentro del sandbox.
    Run {
        /// Prompt en lenguaje natural (p. ej. "write 'hola' to notes/hi.txt")
        prompt: String,
        /// No ejecutar la propuesta — solo mostrarla.
        #[arg(long)]
        dry_run: bool,
    },
    /// Diagnóstico: lanza el sidecar Python y envía un `ping`.
    Ping,
}

#[derive(Subcommand)]
enum SandboxAction {
    /// Muestra la ruta del sandbox resuelta
    Path,
    /// Resumen del estado del kernel: sandbox, audit, keyring.
    Status,
}

#[derive(Serialize)]
struct WriteFileArgs<'a> {
    path: &'a str,
    bytes: usize,
}

#[derive(Serialize)]
struct ReadFileArgs<'a> {
    path: &'a str,
}

#[derive(Serialize)]
struct ListDirArgs<'a> {
    path: &'a str,
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

fn default_python_cwd() -> PathBuf {
    std::env::current_dir()
        .map(|c| c.join("python-core"))
        .unwrap_or_else(|_| PathBuf::from("python-core"))
}

fn load_audit_store(audit_dir: &Path) -> Result<AuditStore, i32> {
    let (key, created) = match keyring::load_or_create_audit_key() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[reli] error al acceder al keyring: {e}");
            return Err(EXIT_AUDIT);
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
        EXIT_AUDIT
    })
}

fn open_sandbox(sandbox_path: &Path) -> Result<Sandbox, i32> {
    Sandbox::open(sandbox_path).map_err(|e| {
        eprintln!("[reli] error al abrir el sandbox: {e}");
        EXIT_BAD_INPUT
    })
}

fn approval_mode(non_interactive: bool) -> ApprovalMode {
    if non_interactive {
        ApprovalMode::NonInteractive
    } else {
        ApprovalMode::Interactive
    }
}

pub fn run() -> i32 {
    let cli = Cli::parse();
    let sandbox_path = cli.sandbox.unwrap_or_else(default_sandbox_path);
    let audit_dir = cli.audit_dir.unwrap_or_else(default_audit_dir);
    let python = cli.python.unwrap_or_else(|| PathBuf::from("python"));
    let python_cwd = cli.python_cwd.unwrap_or_else(default_python_cwd);
    let non_interactive = cli.non_interactive;

    match cli.command {
        Command::Sandbox { action } => match action {
            SandboxAction::Path => {
                println!("{}", sandbox_path.display());
                EXIT_OK
            }
            SandboxAction::Status => run_sandbox_status(&sandbox_path, &audit_dir),
        },
        Command::Write { path, content } => run_write(&sandbox_path, &audit_dir, &path, &content),
        Command::Read { path } => run_read(&sandbox_path, &audit_dir, &path),
        Command::Ls { path } => run_ls(&sandbox_path, &audit_dir, path.as_deref().unwrap_or("")),
        Command::Verify => run_verify(&audit_dir),
        Command::Reset {
            wipe_everything,
            force,
        } => run_reset(
            &sandbox_path,
            &audit_dir,
            wipe_everything,
            force,
            non_interactive,
        ),
        Command::Ping => run_ping(&python, &python_cwd),
        Command::Run { prompt, dry_run } => run_agent(
            &sandbox_path,
            &audit_dir,
            &python,
            &python_cwd,
            &prompt,
            dry_run,
            non_interactive,
        ),
    }
}

fn spawn_bridge(python: &Path, python_cwd: &Path) -> Result<Bridge, i32> {
    let spec = SidecarSpec::Module {
        python: python.to_path_buf(),
    };
    Bridge::spawn(spec, python_cwd).map_err(|e| {
        eprintln!("[reli] no se pudo lanzar el sidecar Python: {e}");
        eprintln!(
            "[reli] sugerencia: verifique que `{}` esté en PATH y que `{}` contenga el paquete `reliagent_python`.",
            python.display(),
            python_cwd.display()
        );
        EXIT_BRIDGE
    })
}

fn run_ping(python: &Path, python_cwd: &Path) -> i32 {
    let mut bridge = match spawn_bridge(python, python_cwd) {
        Ok(b) => b,
        Err(code) => return code,
    };
    match bridge.ping() {
        Ok(()) => {
            println!("[reli] sidecar ok (ping/pong)");
            let _ = bridge.shutdown();
            EXIT_OK
        }
        Err(e) => {
            eprintln!("[reli] ping falló: {e}");
            EXIT_BRIDGE
        }
    }
}

fn run_agent(
    sandbox_path: &Path,
    audit_dir: &Path,
    python: &Path,
    python_cwd: &Path,
    prompt: &str,
    dry_run: bool,
    non_interactive: bool,
) -> i32 {
    let mut bridge = match spawn_bridge(python, python_cwd) {
        Ok(b) => b,
        Err(code) => return code,
    };

    let result = match bridge.agent_run(prompt) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[reli] agent.run falló: {e}");
            return EXIT_BRIDGE;
        }
    };
    let _ = bridge.shutdown();

    print_agent_result(&result);

    if result.verdict != "approve" {
        return EXIT_REJECTED;
    }
    if dry_run {
        println!("[reli] dry-run: propuesta NO ejecutada");
        return EXIT_OK;
    }

    let proposal = match &result.proposal {
        Some(p) => p,
        None => {
            eprintln!("[reli] approve sin propuesta — no se ejecuta nada");
            return EXIT_BAD_INPUT;
        }
    };

    // Final TTY approval gate (or auto-reject in non-interactive mode).
    let summary = render_proposal_summary(proposal, &result);
    match approval::request_approval(&summary, approval_mode(non_interactive)) {
        ApprovalDecision::Approved => {}
        ApprovalDecision::Rejected => {
            println!("[reli] usuario rechazó la propuesta — no se ejecuta");
            return EXIT_REJECTED;
        }
        ApprovalDecision::AutoRejected => {
            println!("[reli] modo non-interactive — propuesta no ejecutada");
            return EXIT_REJECTED;
        }
        ApprovalDecision::Timeout => {
            println!("[reli] timeout de aprobación — no se ejecuta");
            return EXIT_TIMEOUT;
        }
    }

    execute_proposal(sandbox_path, audit_dir, proposal)
}

fn print_agent_result(result: &AgentRunResult) {
    println!("[reli] agente: verdict={}", result.verdict);
    if !result.critic_stage.is_empty() {
        println!("[reli] crítico: stage={}", result.critic_stage);
    }
    if !result.reason.is_empty() {
        println!("[reli] motivo: {}", result.reason);
    }
    if let Some(p) = &result.proposal {
        println!("[reli] propuesta: {p}");
    }
    for t in &result.trace {
        println!("[reli] trace: {t}");
    }
}

fn render_proposal_summary(proposal: &serde_json::Value, result: &AgentRunResult) -> String {
    let tool = proposal.get("tool").and_then(|v| v.as_str()).unwrap_or("?");
    let args = proposal
        .get("args")
        .map(|v| v.to_string())
        .unwrap_or_else(|| "{}".into());
    format!(
        "[reli] propuesta a ejecutar\n  tool: {tool}\n  args: {args}\n  critic: {} ({})",
        result.verdict, result.critic_stage
    )
}

fn execute_proposal(sandbox_path: &Path, audit_dir: &Path, proposal: &serde_json::Value) -> i32 {
    let tool = proposal.get("tool").and_then(|v| v.as_str()).unwrap_or("");
    let args = match proposal.get("args").and_then(|v| v.as_object()) {
        Some(a) => a,
        None => {
            eprintln!("[reli] propuesta sin args");
            return EXIT_BAD_INPUT;
        }
    };
    let path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p.to_string(),
        None => {
            eprintln!("[reli] propuesta sin args.path");
            return EXIT_BAD_INPUT;
        }
    };

    match tool {
        "write_file" => {
            let content = match args.get("content").and_then(|v| v.as_str()) {
                Some(c) => c.to_string(),
                None => {
                    eprintln!("[reli] propuesta write_file sin args.content");
                    return EXIT_BAD_INPUT;
                }
            };
            run_write(sandbox_path, audit_dir, &path, &content)
        }
        "read_file" => run_read(sandbox_path, audit_dir, &path),
        "list_dir" => run_ls(sandbox_path, audit_dir, &path),
        other => {
            eprintln!("[reli] propuesta con tool no soportado: {other:?}");
            EXIT_BAD_INPUT
        }
    }
}

fn kernel_error_exit(e: &KernelError) -> i32 {
    match e {
        KernelError::PathOutsideSandbox { .. }
        | KernelError::InvalidPath { .. }
        | KernelError::FileTooLarge { .. } => EXIT_REJECTED,
        _ => EXIT_BAD_INPUT,
    }
}

fn run_write(sandbox_path: &Path, audit_dir: &Path, path: &str, content: &str) -> i32 {
    let mut store = match load_audit_store(audit_dir) {
        Ok(s) => s,
        Err(code) => return code,
    };

    let sandbox = match open_sandbox(sandbox_path) {
        Ok(s) => s,
        Err(code) => return code,
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
            return EXIT_AUDIT;
        }
    };

    if let Err(e) = store.verify() {
        eprintln!("[reli] audit store corrupto tras registrar: {e}");
        return EXIT_AUDIT;
    }

    match result {
        Ok(()) => {
            println!(
                "[reli] ok: {} bytes escritos en {}",
                content.len(),
                sandbox.root_path().join(path).display()
            );
            println!("[reli] audit hmac: {record_hmac}");
            EXIT_OK
        }
        Err(e) => {
            eprintln!("[reli] rechazado: {e}");
            eprintln!("[reli] audit hmac: {record_hmac}");
            kernel_error_exit(&e)
        }
    }
}

fn run_read(sandbox_path: &Path, audit_dir: &Path, path: &str) -> i32 {
    let mut store = match load_audit_store(audit_dir) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let sandbox = match open_sandbox(sandbox_path) {
        Ok(s) => s,
        Err(code) => return code,
    };

    let args = ReadFileArgs { path };
    let result = tools::read_file(&sandbox, path);
    let status = match &result {
        Ok(_) => AuditStatus::Ok,
        Err(e) => AuditStatus::Rejected {
            reason: format!("{e}"),
        },
    };

    let record_hmac = match store.record("read_file", &args, status) {
        Ok(signed) => signed.hmac,
        Err(e) => {
            eprintln!("[reli] error registrando en el audit store: {e}");
            return EXIT_AUDIT;
        }
    };

    if let Err(e) = store.verify() {
        eprintln!("[reli] audit store corrupto tras registrar: {e}");
        return EXIT_AUDIT;
    }

    match result {
        Ok(bytes) => {
            use std::io::Write;
            // Write raw bytes to stdout so binary payloads survive.
            // Human-facing status goes to stderr.
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            if let Err(e) = handle.write_all(&bytes) {
                eprintln!("[reli] error escribiendo stdout: {e}");
                return EXIT_BAD_INPUT;
            }
            let _ = handle.flush();
            eprintln!("[reli] ok: {} bytes leídos de {}", bytes.len(), path);
            eprintln!("[reli] audit hmac: {record_hmac}");
            EXIT_OK
        }
        Err(e) => {
            eprintln!("[reli] rechazado: {e}");
            eprintln!("[reli] audit hmac: {record_hmac}");
            kernel_error_exit(&e)
        }
    }
}

fn run_ls(sandbox_path: &Path, audit_dir: &Path, path: &str) -> i32 {
    let mut store = match load_audit_store(audit_dir) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let sandbox = match open_sandbox(sandbox_path) {
        Ok(s) => s,
        Err(code) => return code,
    };

    let normalized = if path.is_empty() { "." } else { path };
    let args = ListDirArgs { path: normalized };
    let result = tools::list_dir(&sandbox, path);
    let status = match &result {
        Ok(_) => AuditStatus::Ok,
        Err(e) => AuditStatus::Rejected {
            reason: format!("{e}"),
        },
    };

    let record_hmac = match store.record("list_dir", &args, status) {
        Ok(signed) => signed.hmac,
        Err(e) => {
            eprintln!("[reli] error registrando en el audit store: {e}");
            return EXIT_AUDIT;
        }
    };

    if let Err(e) = store.verify() {
        eprintln!("[reli] audit store corrupto tras registrar: {e}");
        return EXIT_AUDIT;
    }

    match result {
        Ok(entries) => {
            print_entries(&entries);
            eprintln!("[reli] ok: {} entradas", entries.len());
            eprintln!("[reli] audit hmac: {record_hmac}");
            EXIT_OK
        }
        Err(e) => {
            eprintln!("[reli] rechazado: {e}");
            eprintln!("[reli] audit hmac: {record_hmac}");
            kernel_error_exit(&e)
        }
    }
}

fn print_entries(entries: &[DirEntry]) {
    for e in entries {
        let marker = match e.kind {
            DirEntryKind::Dir => "d",
            DirEntryKind::File => "-",
            DirEntryKind::Other => "?",
        };
        println!("{marker} {}", e.name);
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
            EXIT_OK
        }
        Err(e) => {
            eprintln!("[reli] verify falló: {e}");
            EXIT_AUDIT
        }
    }
}

fn run_sandbox_status(sandbox_path: &Path, audit_dir: &Path) -> i32 {
    println!("[reli] sandbox path: {}", sandbox_path.display());
    println!(
        "[reli] sandbox exists: {}",
        if sandbox_path.exists() { "yes" } else { "no" }
    );
    println!("[reli] audit dir:    {}", audit_dir.display());
    let db_path = audit_dir.join("audit.db");
    println!("[reli] audit db:     {}", db_path.display());

    if !db_path.exists() {
        println!("[reli] audit db:     (todavía no inicializado)");
        println!("[reli] keyring:      {}", keyring::account_label());
        return EXIT_OK;
    }

    match load_audit_store(audit_dir) {
        Ok(store) => {
            println!("[reli] audit entries: {}", store.len());
            println!(
                "[reli] audit last hmac: {}",
                store.last_hmac().unwrap_or("-")
            );
            match store.verify() {
                Ok(()) => println!("[reli] audit verify: ok"),
                Err(e) => println!("[reli] audit verify: FAILED ({e})"),
            }
            println!("[reli] keyring:      {}", keyring::account_label());
            EXIT_OK
        }
        Err(code) => code,
    }
}

fn run_reset(
    sandbox_path: &Path,
    audit_dir: &Path,
    wipe_everything: bool,
    force: bool,
    non_interactive: bool,
) -> i32 {
    if !wipe_everything {
        eprintln!("[reli] reset requiere --wipe-everything (confirmación explícita del alcance)");
        return EXIT_BAD_INPUT;
    }

    println!("[reli] reset alcanzará:");
    println!("  - sandbox:  {}", sandbox_path.display());
    println!("  - audit db: {}", audit_dir.join("audit.db").display());
    println!("  - anchors:  {}", audit_dir.join("anchors").display());
    println!("  - keyring:  {}", keyring::account_label());

    if !force {
        if non_interactive {
            eprintln!("[reli] reset non-interactive sin --force — abortado");
            return EXIT_REJECTED;
        }
        use std::io::Write;
        eprint!("[reli] para confirmar escriba WIPE y enter: ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            eprintln!("[reli] no se pudo leer stdin — abortado");
            return EXIT_REJECTED;
        }
        if line.trim() != "WIPE" {
            eprintln!("[reli] confirmación no coincide — abortado");
            return EXIT_REJECTED;
        }
    }

    let mut failures = 0usize;

    if sandbox_path.exists() {
        match wipe_dir_contents(sandbox_path) {
            Ok(n) => println!("[reli] sandbox limpiado: {n} entradas"),
            Err(e) => {
                eprintln!("[reli] error limpiando sandbox: {e}");
                failures += 1;
            }
        }
    } else {
        println!("[reli] sandbox: no existía");
    }

    let db_path = audit_dir.join("audit.db");
    remove_if_exists(&db_path, "audit.db", &mut failures);
    // SQLite WAL/SHM siblings, if any.
    remove_if_exists(
        &audit_dir.join("audit.db-wal"),
        "audit.db-wal",
        &mut failures,
    );
    remove_if_exists(
        &audit_dir.join("audit.db-shm"),
        "audit.db-shm",
        &mut failures,
    );

    let anchors = audit_dir.join("anchors");
    if anchors.exists() {
        match std::fs::remove_dir_all(&anchors) {
            Ok(()) => println!("[reli] anchors eliminados"),
            Err(e) => {
                eprintln!("[reli] error eliminando anchors: {e}");
                failures += 1;
            }
        }
    } else {
        println!("[reli] anchors: no existían");
    }

    match keyring::delete_audit_key() {
        Ok(true) => println!("[reli] keyring: clave HMAC eliminada"),
        Ok(false) => println!("[reli] keyring: no había clave almacenada"),
        Err(e) => {
            eprintln!("[reli] error eliminando clave keyring: {e}");
            failures += 1;
        }
    }

    if failures == 0 {
        println!("[reli] reset completo");
        EXIT_OK
    } else {
        eprintln!("[reli] reset terminó con {failures} error(es)");
        EXIT_AUDIT
    }
}

fn remove_if_exists(path: &Path, label: &str, failures: &mut usize) {
    if !path.exists() {
        println!("[reli] {label}: no existía");
        return;
    }
    match std::fs::remove_file(path) {
        Ok(()) => println!("[reli] {label} eliminado"),
        Err(e) => {
            eprintln!("[reli] error eliminando {label}: {e}");
            *failures += 1;
        }
    }
}

fn wipe_dir_contents(dir: &Path) -> std::io::Result<usize> {
    let mut removed = 0usize;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        let path = entry.path();
        if ft.is_dir() {
            std::fs::remove_dir_all(&path)?;
        } else {
            std::fs::remove_file(&path)?;
        }
        removed += 1;
    }
    Ok(removed)
}
