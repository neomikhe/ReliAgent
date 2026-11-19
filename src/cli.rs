use clap::{Parser, Subcommand};
use serde::Serialize;
use std::path::{Path, PathBuf};

use reliagent::approval::{self, ApprovalDecision, ApprovalMode};
use reliagent::bridge::{AgentRunResult, Bridge, LlmBackend, SidecarSpec, rpc_codes};
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
    /// Usa Ollama en 127.0.0.1:11434 con el modelo fijado en MODEL_SHA256.txt.
    Run {
        /// Prompt en lenguaje natural (p. ej. "write 'hola' to notes/hi.txt")
        prompt: String,
        /// No ejecutar la propuesta — solo mostrarla.
        #[arg(long)]
        dry_run: bool,
        /// Usar el agente determinista de pruebas en lugar de Ollama (no
        /// requiere Ollama ni el modelo; solo entiende frases simples como
        /// "write 'x' to a.txt", "read a.txt" o "list").
        #[arg(long)]
        mock_llm: bool,
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
        Command::Run {
            prompt,
            dry_run,
            mock_llm,
        } => run_agent(
            &sandbox_path,
            &audit_dir,
            &python,
            &python_cwd,
            &prompt,
            dry_run,
            non_interactive,
            llm_backend(mock_llm),
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
            eprintln!("[reli] ping falló: {}", error_text(&e));
            EXIT_BRIDGE
        }
    }
}

/// Escapa los caracteres que la terminal interpretaría: controles C0/C1,
/// DEL y caracteres de formato/bidi. Todo texto que venga del sidecar, del
/// LLM o del sistema de archivos pasa por aquí antes de imprimirse, para
/// que nadie pueda borrar la pantalla, falsificar mensajes, crear enlaces
/// OSC 8 o escribir en el portapapeles (OSC 52).
fn sanitize_for_terminal(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let unsafe_char = c.is_control()
            || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}');
        if unsafe_char {
            let _ = write!(out, "\\u{{{:x}}}", c as u32);
        } else {
            out.push(c);
        }
    }
    out
}

fn error_text(e: &KernelError) -> String {
    sanitize_for_terminal(&e.to_string())
}

fn llm_backend(mock_llm: bool) -> LlmBackend {
    if mock_llm {
        LlmBackend::Mock
    } else {
        LlmBackend::Ollama
    }
}

/// Instrucciones para el usuario según el error de aplicación del sidecar.
fn sidecar_hint(err: &KernelError) -> Option<String> {
    let KernelError::SidecarRpc { code, data, .. } = err else {
        return None;
    };
    let hint = match *code {
        rpc_codes::OLLAMA_UNREACHABLE => "[reli] Ollama no detectado en 127.0.0.1:11434.\n\
             [reli]   Instálalo desde https://ollama.com y arráncalo (app de escritorio u `ollama serve`).\n\
             [reli]     Linux/macOS: curl -fsSL https://ollama.com/install.sh | sh\n\
             [reli]     Windows: descarga el instalador desde https://ollama.com\n\
             [reli]   Para probar sin Ollama: reli run --mock-llm \"<prompt>\""
            .to_string(),
        rpc_codes::MODEL_MISSING => {
            let model = data
                .as_ref()
                .and_then(|d| d.get("model"))
                .and_then(|m| m.as_str())
                .filter(|m| is_safe_model_tag(m));
            match model {
                Some(m) => format!(
                    "[reli] Ollama no tiene el modelo fijado. Descárgalo con:\n[reli]   ollama pull {m}"
                ),
                None => "[reli] Ollama no tiene el modelo fijado. Descarga la etiqueta indicada en MODEL_SHA256.txt con `ollama pull`.".to_string(),
            }
        }
        rpc_codes::MODEL_INTEGRITY => "[reli] El modelo que sirve Ollama no coincide con el SHA-256 fijado en MODEL_SHA256.txt.\n\
             [reli]   No se ejecutó ninguna inferencia. Vuelve a descargarlo (`ollama rm` + `ollama pull`);\n\
             [reli]   si el error persiste, trátalo como una posible manipulación del modelo."
            .to_string(),
        rpc_codes::LLM_ERROR => {
            "[reli] Ollama falló durante la generación. Revisa los logs de Ollama y reintenta."
                .to_string()
        }
        _ => return None,
    };
    Some(hint)
}

/// Etiqueta de Ollama con caracteres seguros para mostrar en la terminal.
fn is_safe_model_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 128
        && tag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '-'))
}

#[allow(clippy::too_many_arguments)]
fn run_agent(
    sandbox_path: &Path,
    audit_dir: &Path,
    python: &Path,
    python_cwd: &Path,
    prompt: &str,
    dry_run: bool,
    non_interactive: bool,
    backend: LlmBackend,
) -> i32 {
    let mut bridge = match spawn_bridge(python, python_cwd) {
        Ok(b) => b,
        Err(code) => return code,
    };

    let result = match bridge.agent_run(prompt, backend) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[reli] agent.run falló: {}", error_text(&e));
            if let Some(hint) = sidecar_hint(&e) {
                eprintln!("{hint}");
            }
            return EXIT_BRIDGE;
        }
    };
    let _ = bridge.shutdown();

    for line in agent_result_lines(&result) {
        println!("{line}");
    }

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

/// Líneas a mostrar del resultado del agente, ya saneadas.
fn agent_result_lines(result: &AgentRunResult) -> Vec<String> {
    let mut lines = vec![format!("[reli] agente: verdict={}", result.verdict)];
    if !result.critic_stage.is_empty() {
        lines.push(format!("[reli] crítico: stage={}", result.critic_stage));
    }
    if !result.reason.is_empty() {
        lines.push(format!("[reli] motivo: {}", result.reason));
    }
    if let Some(p) = &result.proposal {
        lines.push(format!("[reli] propuesta: {p}"));
    }
    for t in &result.trace {
        lines.push(format!("[reli] trace: {t}"));
    }
    lines.iter().map(|l| sanitize_for_terminal(l)).collect()
}

fn render_proposal_summary(proposal: &serde_json::Value, result: &AgentRunResult) -> String {
    let tool = proposal.get("tool").and_then(|v| v.as_str()).unwrap_or("?");
    let args = proposal
        .get("args")
        .map(|v| v.to_string())
        .unwrap_or_else(|| "{}".into());
    format!(
        "[reli] propuesta a ejecutar\n  tool: {}\n  args: {}\n  critic: {} ({})",
        sanitize_for_terminal(tool),
        sanitize_for_terminal(&args),
        sanitize_for_terminal(&result.verdict),
        sanitize_for_terminal(&result.critic_stage)
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
                sanitize_for_terminal(&sandbox.root_path().join(path).display().to_string())
            );
            println!("[reli] audit hmac: {record_hmac}");
            EXIT_OK
        }
        Err(e) => {
            eprintln!("[reli] rechazado: {}", error_text(&e));
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
            eprintln!(
                "[reli] ok: {} bytes leídos de {}",
                bytes.len(),
                sanitize_for_terminal(path)
            );
            eprintln!("[reli] audit hmac: {record_hmac}");
            EXIT_OK
        }
        Err(e) => {
            eprintln!("[reli] rechazado: {}", error_text(&e));
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
            for entry in &entries {
                println!("{}", entry_line(entry));
            }
            eprintln!("[reli] ok: {} entradas", entries.len());
            eprintln!("[reli] audit hmac: {record_hmac}");
            EXIT_OK
        }
        Err(e) => {
            eprintln!("[reli] rechazado: {}", error_text(&e));
            eprintln!("[reli] audit hmac: {record_hmac}");
            kernel_error_exit(&e)
        }
    }
}

fn entry_line(e: &DirEntry) -> String {
    let marker = match e.kind {
        DirEntryKind::Dir => "d",
        DirEntryKind::File => "-",
        DirEntryKind::Other => "?",
    };
    format!("{marker} {}", sanitize_for_terminal(&e.name))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Ningún carácter que la terminal pueda interpretar como control.
    fn assert_terminal_safe(s: &str) {
        for c in s.chars() {
            assert!(
                !c.is_control()
                    && !matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'),
                "unsafe char {:?} in {s:?}",
                c
            );
        }
    }

    const HOSTILE: &str = "a\u{1b}]52;c;aGk=\u{7}b\u{1b}[2Jc\u{9b}d\u{7f}e\u{202e}f\u{200b}g\nh\ri";

    #[test]
    fn sanitize_escapes_control_and_bidi_chars() {
        let out = sanitize_for_terminal(HOSTILE);
        assert_terminal_safe(&out);
        assert!(out.contains("\\u{1b}"), "{out}");
        assert!(out.contains("\\u{202e}"), "{out}");
    }

    #[test]
    fn sanitize_keeps_plain_text_untouched() {
        let s = "ñandú café — notes/a b.txt 123 [ok] {\"k\":1}";
        assert_eq!(sanitize_for_terminal(s), s);
    }

    #[test]
    fn agent_result_lines_are_terminal_safe() {
        let result = AgentRunResult {
            proposal: Some(serde_json::json!({"tool": null, "reason": HOSTILE})),
            verdict: format!("reject{HOSTILE}"),
            reason: HOSTILE.into(),
            agent_raw: String::new(),
            critic_stage: HOSTILE.into(),
            trace: vec![HOSTILE.into()],
        };
        let lines = agent_result_lines(&result);
        assert!(lines.len() >= 5);
        lines.iter().for_each(|l| assert_terminal_safe(l));
    }

    #[test]
    fn proposal_summary_is_terminal_safe() {
        let result = AgentRunResult {
            proposal: None,
            verdict: "approve".into(),
            reason: String::new(),
            agent_raw: String::new(),
            critic_stage: HOSTILE.into(),
            trace: vec![],
        };
        let proposal = serde_json::json!({"tool": HOSTILE, "args": {"path": HOSTILE}});
        let summary = render_proposal_summary(&proposal, &result);
        summary.lines().for_each(assert_terminal_safe);
    }

    #[test]
    fn error_lines_are_terminal_safe() {
        let err = KernelError::SidecarRpc {
            code: -32012,
            message: HOSTILE.into(),
            data: None,
        };
        assert_terminal_safe(&error_text(&err));
        let err = KernelError::PathOutsideSandbox {
            path: HOSTILE.into(),
        };
        assert_terminal_safe(&error_text(&err));
    }

    #[test]
    fn dir_entry_names_are_terminal_safe() {
        let entry = DirEntry {
            name: HOSTILE.into(),
            kind: DirEntryKind::File,
        };
        assert_terminal_safe(&entry_line(&entry));
    }

    fn parse_run(args: &[&str]) -> (String, bool) {
        let cli = Cli::try_parse_from(args).expect("valid args");
        match cli.command {
            Command::Run {
                prompt, mock_llm, ..
            } => (prompt, mock_llm),
            _ => panic!("expected run"),
        }
    }

    fn rpc_error(code: i64, data: Option<serde_json::Value>) -> KernelError {
        KernelError::SidecarRpc {
            code,
            message: "x".into(),
            data,
        }
    }

    #[test]
    fn run_uses_ollama_by_default() {
        let (prompt, mock_llm) = parse_run(&["reli", "run", "hola"]);
        assert_eq!(prompt, "hola");
        assert!(!mock_llm);
        assert_eq!(llm_backend(mock_llm), LlmBackend::Ollama);
    }

    #[test]
    fn mock_llm_flag_selects_mock_backend() {
        let (_, mock_llm) = parse_run(&["reli", "run", "--mock-llm", "hola"]);
        assert!(mock_llm);
        assert_eq!(llm_backend(mock_llm), LlmBackend::Mock);
    }

    #[test]
    fn unreachable_hint_explains_install_and_mock() {
        let hint = sidecar_hint(&rpc_error(rpc_codes::OLLAMA_UNREACHABLE, None)).unwrap();
        assert!(hint.contains("127.0.0.1:11434"), "{hint}");
        assert!(hint.contains("https://ollama.com"), "{hint}");
        assert!(hint.contains("--mock-llm"), "{hint}");
    }

    #[test]
    fn missing_model_hint_names_pull_command() {
        let data =
            serde_json::json!({"kind": "model_missing", "model": "qwen2.5:7b-instruct-q4_K_M"});
        let hint = sidecar_hint(&rpc_error(rpc_codes::MODEL_MISSING, Some(data))).unwrap();
        assert!(
            hint.contains("ollama pull qwen2.5:7b-instruct-q4_K_M"),
            "{hint}"
        );
    }

    #[test]
    fn missing_model_hint_ignores_unsafe_model_names() {
        // El nombre viene del sidecar; nunca se imprime algo que no parezca
        // una etiqueta de Ollama (p. ej. secuencias de escape de terminal).
        let data = serde_json::json!({"model": "x\u{1b}[2J; rm -rf ~"});
        let hint = sidecar_hint(&rpc_error(rpc_codes::MODEL_MISSING, Some(data))).unwrap();
        assert!(!hint.contains('\u{1b}'), "{hint:?}");
        assert!(!hint.contains("rm -rf"), "{hint}");
        assert!(hint.contains("MODEL_SHA256.txt"), "{hint}");
    }

    #[test]
    fn integrity_hint_says_nothing_ran() {
        let hint = sidecar_hint(&rpc_error(rpc_codes::MODEL_INTEGRITY, None)).unwrap();
        assert!(hint.contains("MODEL_SHA256.txt"), "{hint}");
        assert!(hint.contains("ninguna inferencia"), "{hint}");
    }

    #[test]
    fn llm_error_has_hint() {
        assert!(sidecar_hint(&rpc_error(rpc_codes::LLM_ERROR, None)).is_some());
    }

    #[test]
    fn other_errors_have_no_hint() {
        assert!(sidecar_hint(&rpc_error(-32603, None)).is_none());
        assert!(sidecar_hint(&KernelError::Bridge("x".into())).is_none());
    }
}
