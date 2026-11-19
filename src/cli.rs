use clap::{Parser, Subcommand};
use serde::Serialize;
use std::path::{Path, PathBuf};

use reliagent::approval::{self, ApprovalDecision, ApprovalMode};
use reliagent::bridge::{AgentRunResult, Bridge, LlmBackend, SidecarSpec, rpc_codes};
use reliagent::kernel::audit::{AuditStatus, SignedEntry};
use reliagent::kernel::keyring;
use reliagent::kernel::policy::{MAX_FILE_SIZE, validate_write_path};
use reliagent::kernel::sandbox::Sandbox;
use reliagent::kernel::store::{AuditStore, LogLock};
use reliagent::kernel::tools::{DirEntry, DirEntryKind};
use reliagent::kernel::{KernelError, KernelResult, tools};

/// Exit codes (documented contract — changing these breaks scripts).
/// 0 success
/// 1 policy/agent/user rejected
/// 2 malformed input / unsupported proposal
/// 3 audit or keyring failure (incl. a log that fails verification)
/// 4 bridge / sidecar failure
/// 5 approval timeout
/// 6 audit log in use by another process (not a sign of tampering)
const EXIT_OK: i32 = 0;
const EXIT_REJECTED: i32 = 1;
const EXIT_BAD_INPUT: i32 = 2;
const EXIT_AUDIT: i32 = 3;
const EXIT_BRIDGE: i32 = 4;
const EXIT_TIMEOUT: i32 = 5;
const EXIT_BUSY: i32 = 6;

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
            eprintln!("[reli] error al acceder al keyring: {}", error_text(&e));
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
    let opened = keyring::KeyringHead::for_log(&db_path)
        .and_then(|head| AuditStore::open_with_head(&db_path, &anchor_dir, key, Box::new(head)));
    opened.map_err(|e| {
        // El texto puede venir del propio archivo (manipulado): se sanea.
        eprintln!("[reli] error inicializando audit store: {}", error_text(&e));
        if matches!(e, KernelError::AuditCorrupted { .. }) {
            eprintln!(
                "[reli] el log no supera la verificación; si borraste ~/.reliagent a mano, \
                 usa `reli reset --wipe-everything`"
            );
        }
        store_error_exit(&e)
    })
}

/// Código de salida de un error al abrir o usar el log.
fn store_error_exit(e: &KernelError) -> i32 {
    match e {
        KernelError::AuditBusy => EXIT_BUSY,
        _ => EXIT_AUDIT,
    }
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
        // Órdenes directas del usuario: la propia orden es la aprobación.
        Command::Write { path, content } => run_action(
            &sandbox_path,
            &audit_dir,
            &Action::Write { path, content },
            || ApprovalDecision::Approved,
        ),
        Command::Read { path } => {
            run_action(&sandbox_path, &audit_dir, &Action::Read { path }, || {
                ApprovalDecision::Approved
            })
        }
        Command::Ls { path } => run_action(
            &sandbox_path,
            &audit_dir,
            &Action::List {
                path: path.unwrap_or_default(),
            },
            || ApprovalDecision::Approved,
        ),
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
    escape_unsafe_chars(s, &[])
}

/// Contenido de un archivo para mostrarlo en una terminal: conserva saltos
/// de línea y tabuladores, escapa el resto de controles (incluido `\r`, que
/// permitiría sobrescribir la línea) y sustituye bytes que no son UTF-8.
fn display_safe(bytes: &[u8]) -> String {
    escape_unsafe_chars(&String::from_utf8_lossy(bytes), &['\n', '\t'])
}

fn escape_unsafe_chars(s: &str, keep: &[char]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let unsafe_char = (c.is_control() && !keep.contains(&c))
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
    let action = match parse_proposal(proposal) {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("[reli] {}", sanitize_for_terminal(&msg));
            return EXIT_BAD_INPUT;
        }
    };

    // La propuesta queda registrada como `pending` antes de pedir la
    // aprobación final por TTY (o rechazarla en modo non-interactive).
    let summary = render_proposal_summary(proposal, &result);
    let mode = approval_mode(non_interactive);
    run_action(sandbox_path, audit_dir, &action, || {
        approval::request_approval(&summary, mode)
    })
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

/// Acción del kernel, venga de la CLI (`reli write/read/ls`) o de una
/// propuesta del agente ya validada.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Action {
    Write { path: String, content: String },
    Read { path: String },
    List { path: String },
}

/// Argumentos que se registran (y hashean) en el log. Mismas formas que
/// antes de la fase 2, para que el `args_hash` de una acción no cambie.
#[derive(Serialize)]
#[serde(untagged)]
enum AuditArgs<'a> {
    Write(WriteFileArgs<'a>),
    Read(ReadFileArgs<'a>),
    List(ListDirArgs<'a>),
}

impl Action {
    fn tool(&self) -> &'static str {
        match self {
            Action::Write { .. } => "write_file",
            Action::Read { .. } => "read_file",
            Action::List { .. } => "list_dir",
        }
    }

    fn audit_args(&self) -> AuditArgs<'_> {
        match self {
            Action::Write { path, content } => AuditArgs::Write(WriteFileArgs {
                path,
                bytes: content.len(),
            }),
            Action::Read { path } => AuditArgs::Read(ReadFileArgs { path }),
            Action::List { path } => AuditArgs::List(ListDirArgs {
                path: if path.is_empty() { "." } else { path },
            }),
        }
    }

    fn path(&self) -> &str {
        match self {
            Action::Write { path, .. } | Action::Read { path } | Action::List { path } => path,
        }
    }
}

/// Resultado de una acción ejecutada con éxito.
#[derive(Debug)]
enum Executed {
    Wrote(usize),
    ReadBytes(Vec<u8>),
    Listed(Vec<DirEntry>),
}

/// Por qué una acción no se completó.
#[derive(Debug)]
enum Refusal {
    /// No hubo aprobación (usuario, timeout o modo non-interactive).
    Approval(ApprovalDecision),
    /// El kernel la rechazó (política) o falló al ejecutarla (E/S).
    Kernel(KernelError),
}

/// Convierte la propuesta del sidecar en una `Action`. No ejecuta nada.
fn parse_proposal(proposal: &serde_json::Value) -> Result<Action, String> {
    let tool = proposal.get("tool").and_then(|v| v.as_str()).unwrap_or("");
    let args = proposal
        .get("args")
        .and_then(|v| v.as_object())
        .ok_or("propuesta sin args")?;
    let path = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or("propuesta sin args.path")?
        .to_string();
    match tool {
        "write_file" => {
            let content = args
                .get("content")
                .and_then(|v| v.as_str())
                .ok_or("propuesta write_file sin args.content")?
                .to_string();
            Ok(Action::Write { path, content })
        }
        "read_file" => Ok(Action::Read { path }),
        "list_dir" => Ok(Action::List { path }),
        other => Err(format!("propuesta con tool no soportado: {other:?}")),
    }
}

/// Motivo registrado cuando no hay aprobación.
fn approval_reason(decision: ApprovalDecision) -> &'static str {
    match decision {
        ApprovalDecision::Approved => "approved",
        ApprovalDecision::Rejected => "user_denied",
        ApprovalDecision::Timeout => "timeout",
        ApprovalDecision::AutoRejected => "non_interactive",
    }
}

fn is_policy_rejection(e: &KernelError) -> bool {
    matches!(
        e,
        KernelError::PathOutsideSandbox { .. }
            | KernelError::InvalidPath { .. }
            | KernelError::FileTooLarge { .. }
    )
}

/// Motivo que se guarda en el log. Nunca incluye la ruta ni texto del SO:
/// los argumentos solo constan como `args_hash`, y la ruta la puede elegir
/// el LLM.
fn audit_reason(e: &KernelError) -> String {
    match e {
        KernelError::PathOutsideSandbox { .. } => "policy: path_outside_sandbox".into(),
        // Los motivos de InvalidPath son textos fijos del kernel.
        KernelError::InvalidPath { reason } => format!("policy: invalid_path ({reason})"),
        KernelError::FileTooLarge { actual, max } => {
            format!("policy: file_too_large ({actual} > {max} bytes)")
        }
        KernelError::Io(io) => format!("io: {:?}", io.kind()),
        _ => "error: unexpected kernel error".into(),
    }
}

fn refusal_status(e: &KernelError) -> AuditStatus {
    let reason = audit_reason(e);
    if is_policy_rejection(e) {
        AuditStatus::Rejected { reason }
    } else {
        AuditStatus::Error { reason }
    }
}

/// Reglas del motor de políticas que no dependen del disco. Se evalúan
/// antes de preguntar al humano (las herramientas las repiten al ejecutar).
fn precheck(action: &Action) -> KernelResult<()> {
    match action {
        Action::Write { path, content } => {
            if content.len() > MAX_FILE_SIZE {
                return Err(KernelError::FileTooLarge {
                    actual: content.len(),
                    max: MAX_FILE_SIZE,
                });
            }
            validate_write_path(path).map(|_| ())
        }
        Action::Read { path } => validate_write_path(path).map(|_| ()),
        Action::List { path } if path.is_empty() || path == "." => Ok(()),
        Action::List { path } => validate_write_path(path).map(|_| ()),
    }
}

fn perform(sandbox: &Sandbox, action: &Action) -> KernelResult<Executed> {
    match action {
        Action::Write { path, content } => tools::write_file(sandbox, path, content.as_bytes())
            .map(|()| Executed::Wrote(content.len())),
        Action::Read { path } => tools::read_file(sandbox, path).map(Executed::ReadBytes),
        Action::List { path } => tools::list_dir(sandbox, path).map(Executed::Listed),
    }
}

/// Núcleo auditado: `pending` → política → aprobación → ejecución →
/// resolución. Todo lo que va dentro del closure ocurre solo si el
/// `pending` ya está persistido (garantía de `AuditStore::run_audited`).
fn execute_audited(
    store: &mut AuditStore,
    sandbox: &Sandbox,
    action: &Action,
    approve: impl FnOnce() -> ApprovalDecision,
) -> KernelResult<(Result<Executed, Refusal>, SignedEntry)> {
    store.run_audited(action.tool(), &action.audit_args(), || {
        // El motor de políticas va antes que el humano: así una propuesta
        // que intenta salir del sandbox consta como tal, no como
        // `user_denied`, y nadie tiene que decidir sobre ella.
        if let Err(e) = precheck(action) {
            let status = refusal_status(&e);
            return (Err(Refusal::Kernel(e)), status);
        }
        let decision = approve();
        if decision != ApprovalDecision::Approved {
            let status = AuditStatus::Rejected {
                reason: approval_reason(decision).into(),
            };
            return (Err(Refusal::Approval(decision)), status);
        }
        match perform(sandbox, action) {
            Ok(done) => (Ok(done), AuditStatus::Ok),
            Err(e) => {
                let status = refusal_status(&e);
                (Err(Refusal::Kernel(e)), status)
            }
        }
    })
}

/// Abre el log y el sandbox, ejecuta la acción auditada e informa.
fn run_action(
    sandbox_path: &Path,
    audit_dir: &Path,
    action: &Action,
    approve: impl FnOnce() -> ApprovalDecision,
) -> i32 {
    let mut store = match load_audit_store(audit_dir) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let sandbox = match open_sandbox(sandbox_path) {
        Ok(s) => s,
        Err(code) => return code,
    };
    match store.resolve_orphans() {
        Ok(closed) => {
            for orphan in &closed {
                eprintln!(
                    "[reli] seq {} ({}, {}) quedó sin resultado en una sesión anterior: \
                     registrada como `abandoned` (puede que se ejecutara o no; revisa el sandbox)",
                    orphan.sequence_no,
                    sanitize_for_terminal(&orphan.tool),
                    sanitize_for_terminal(&orphan.timestamp)
                );
            }
        }
        Err(e) => {
            eprintln!(
                "[reli] error registrando en el audit store: {}",
                error_text(&e)
            );
            return store_error_exit(&e);
        }
    }

    let (result, resolution) = match execute_audited(&mut store, &sandbox, action, approve) {
        Ok(r) => r,
        Err(e) => {
            // El mensaje dice si la acción llegó a ejecutarse (ver run_audited).
            eprintln!("[reli] error del audit store: {}", error_text(&e));
            return store_error_exit(&e);
        }
    };
    if let Err(e) = store.verify() {
        eprintln!(
            "[reli] audit store corrupto tras registrar: {}",
            error_text(&e)
        );
        return EXIT_AUDIT;
    }
    let hmac = resolution.hmac;
    // Liberar el log antes de escribir en stdout: un pipe lleno no debe
    // dejarlo bloqueado para otros procesos.
    drop(store);
    report(&sandbox, action, result, &hmac)
}

/// Mensajes y código de salida de una acción ya registrada.
fn report(
    sandbox: &Sandbox,
    action: &Action,
    result: Result<Executed, Refusal>,
    hmac: &str,
) -> i32 {
    let path = sanitize_for_terminal(action.path());
    // `reli write` siempre imprimió el hmac en stdout; el resto, en stderr.
    let mut hmac_to_stdout = false;
    let code = match result {
        Ok(Executed::Wrote(n)) => {
            let full = sandbox.root_path().join(action.path());
            println!(
                "[reli] ok: {n} bytes escritos en {}",
                sanitize_for_terminal(&full.display().to_string())
            );
            hmac_to_stdout = true;
            EXIT_OK
        }
        Ok(Executed::ReadBytes(bytes)) => {
            use std::io::{IsTerminal, Write};
            // A un pipe o archivo, bytes crudos (como `cat`). A una terminal,
            // texto con los caracteres de control escapados: el contenido
            // puede haberlo escrito el LLM. El estado va a stderr.
            let stdout = std::io::stdout();
            let shown = if stdout.is_terminal() {
                display_safe(&bytes).into_bytes()
            } else {
                bytes.clone()
            };
            let mut handle = stdout.lock();
            if let Err(e) = handle.write_all(&shown).and_then(|()| handle.flush()) {
                eprintln!("[reli] error escribiendo stdout: {e}");
                return EXIT_BAD_INPUT;
            }
            eprintln!("[reli] ok: {} bytes leídos de {path}", bytes.len());
            EXIT_OK
        }
        Ok(Executed::Listed(entries)) => {
            for entry in &entries {
                println!("{}", entry_line(entry));
            }
            eprintln!("[reli] ok: {} entradas", entries.len());
            EXIT_OK
        }
        Err(Refusal::Approval(decision)) => {
            let (msg, code) = match decision {
                ApprovalDecision::Timeout => {
                    ("timeout de aprobación — no se ejecuta", EXIT_TIMEOUT)
                }
                ApprovalDecision::AutoRejected => (
                    "modo non-interactive — propuesta no ejecutada",
                    EXIT_REJECTED,
                ),
                _ => (
                    "usuario rechazó la propuesta — no se ejecuta",
                    EXIT_REJECTED,
                ),
            };
            println!("[reli] {msg}");
            code
        }
        Err(Refusal::Kernel(e)) => {
            eprintln!("[reli] rechazado: {}", error_text(&e));
            if is_policy_rejection(&e) {
                EXIT_REJECTED
            } else {
                EXIT_BAD_INPUT
            }
        }
    };
    if hmac_to_stdout {
        println!("[reli] audit hmac: {hmac}");
    } else {
        eprintln!("[reli] audit hmac: {hmac}");
    }
    code
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
            print_open_actions(&store);
            EXIT_OK
        }
        Err(e) => {
            eprintln!("[reli] verify falló: {}", error_text(&e));
            EXIT_AUDIT
        }
    }
}

/// Avisa de acciones `pending` sin resultado (p. ej. tras un crash).
fn print_open_actions(store: &AuditStore) {
    let open = store.unresolved_pending();
    if !open.is_empty() {
        println!(
            "[reli] acciones sin resultado registrado: {open:?} — la próxima acción las \
             registrará como `abandoned`"
        );
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
                Err(e) => println!("[reli] audit verify: FAILED ({})", error_text(&e)),
            }
            print_open_actions(&store);
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
    println!(
        "  - backup:   {}",
        audit_dir.join("audit.db.schema1.bak").display()
    );
    println!("  - keyring:  {}", keyring::account_label());
    println!(
        "  - testigo:  {}",
        keyring::head_label(&audit_dir.join("audit.db"))
    );

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

    // No borrar nada mientras otro proceso usa el log (p. ej. un `reli run`
    // esperando aprobación). Funciona aunque el log esté corrupto: no lo
    // carga ni lo verifica.
    let db_path = audit_dir.join("audit.db");
    let lock = if db_path.exists() {
        match LogLock::acquire(&db_path) {
            Ok(lock) => Some(lock),
            Err(KernelError::AuditBusy) => {
                eprintln!(
                    "[reli] {} — reset abortado, no se borró nada",
                    error_text(&KernelError::AuditBusy)
                );
                return EXIT_BUSY;
            }
            Err(e) => {
                // Un archivo dañado no debe impedir la recuperación.
                eprintln!(
                    "[reli] aviso: no se pudo bloquear audit.db ({}); se continúa",
                    error_text(&e)
                );
                None
            }
        }
    } else {
        None
    };

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

    match keyring::delete_head(&db_path) {
        Ok(true) => println!("[reli] keyring: testigo de cabeza eliminado"),
        Ok(false) => println!("[reli] keyring: no había testigo de cabeza"),
        Err(e) => {
            eprintln!(
                "[reli] error eliminando el testigo de cabeza: {}",
                error_text(&e)
            );
            failures += 1;
        }
    }

    match keyring::delete_audit_key() {
        Ok(true) => println!("[reli] keyring: clave HMAC eliminada"),
        Ok(false) => println!("[reli] keyring: no había clave almacenada"),
        Err(e) => {
            eprintln!("[reli] error eliminando clave keyring: {}", error_text(&e));
            failures += 1;
        }
    }

    // El lock se suelta justo antes de borrar la base: en Windows no se puede
    // borrar un archivo abierto.
    drop(lock);
    remove_if_exists(&db_path, "audit.db", &mut failures);
    remove_if_exists(
        &audit_dir.join("audit.db.schema1.bak"),
        "audit.db.schema1.bak",
        &mut failures,
    );
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

    // --- Acciones auditadas (pending antes de actuar) ----------------------

    use reliagent::kernel::audit::AuditStatus;
    use tempfile::TempDir;

    struct Env {
        _tmp: TempDir,
        store: AuditStore,
        sandbox: Sandbox,
    }

    fn env() -> Env {
        let tmp = TempDir::new().unwrap();
        let store = AuditStore::open(
            &tmp.path().join("audit.db"),
            &tmp.path().join("anchors"),
            vec![0x42; 32],
        )
        .unwrap();
        let sandbox = Sandbox::open(tmp.path().join("sandbox")).unwrap();
        Env {
            _tmp: tmp,
            store,
            sandbox,
        }
    }

    fn write_action(path: &str) -> Action {
        Action::Write {
            path: path.into(),
            content: "hola".into(),
        }
    }

    fn logged(store: &AuditStore) -> Vec<(AuditStatus, Option<u64>)> {
        store
            .entries()
            .iter()
            .map(|s| (s.entry.status.clone(), s.entry.resolves))
            .collect()
    }

    #[test]
    fn approved_action_runs_and_is_logged_as_pending_then_ok() {
        let mut e = env();
        let (result, _) = execute_audited(&mut e.store, &e.sandbox, &write_action("a.txt"), || {
            ApprovalDecision::Approved
        })
        .unwrap();
        assert!(matches!(result, Ok(Executed::Wrote(4))));
        assert!(e.sandbox.root_path().join("a.txt").exists());
        assert_eq!(
            logged(&e.store),
            vec![(AuditStatus::Pending, None), (AuditStatus::Ok, Some(0))]
        );
    }

    #[test]
    fn refused_proposals_are_logged_and_never_executed() {
        for (decision, reason) in [
            (ApprovalDecision::Rejected, "user_denied"),
            (ApprovalDecision::Timeout, "timeout"),
            (ApprovalDecision::AutoRejected, "non_interactive"),
        ] {
            let mut e = env();
            let (result, _) =
                execute_audited(&mut e.store, &e.sandbox, &write_action("a.txt"), || {
                    decision
                })
                .unwrap();
            assert!(matches!(result, Err(Refusal::Approval(d)) if d == decision));
            assert!(!e.sandbox.root_path().join("a.txt").exists());
            assert_eq!(
                logged(&e.store),
                vec![
                    (AuditStatus::Pending, None),
                    (
                        AuditStatus::Rejected {
                            reason: reason.into()
                        },
                        Some(0)
                    )
                ],
                "{decision:?}"
            );
        }
    }

    #[test]
    fn policy_violation_is_rejected_before_asking_and_logged_without_the_path() {
        // El motor de políticas va antes que el humano: un intento de salir
        // del sandbox queda como `policy`, no como `user_denied`.
        let mut e = env();
        let (result, _) = execute_audited(
            &mut e.store,
            &e.sandbox,
            &write_action("../secreto.txt"),
            || panic!("the human must not be asked about a policy violation"),
        )
        .unwrap();
        assert!(matches!(
            result,
            Err(Refusal::Kernel(KernelError::PathOutsideSandbox { .. }))
        ));
        let (status, resolves) = logged(&e.store)[1].clone();
        assert_eq!(resolves, Some(0));
        assert_eq!(
            status,
            AuditStatus::Rejected {
                reason: "policy: path_outside_sandbox".into()
            }
        );
    }

    #[test]
    fn oversized_write_is_rejected_before_asking() {
        let mut e = env();
        let big = Action::Write {
            path: "big.txt".into(),
            content: "x".repeat(reliagent::kernel::policy::MAX_FILE_SIZE + 1),
        };
        let (result, _) =
            execute_audited(&mut e.store, &e.sandbox, &big, || panic!("must not ask")).unwrap();
        assert!(matches!(
            result,
            Err(Refusal::Kernel(KernelError::FileTooLarge { .. }))
        ));
    }

    #[test]
    fn io_failure_is_logged_as_error_with_its_kind_only() {
        let mut e = env();
        let read = Action::Read {
            path: "missing.txt".into(),
        };
        let (result, _) = execute_audited(&mut e.store, &e.sandbox, &read, || {
            ApprovalDecision::Approved
        })
        .unwrap();
        assert!(matches!(result, Err(Refusal::Kernel(KernelError::Io(_)))));
        assert_eq!(
            logged(&e.store)[1],
            (
                AuditStatus::Error {
                    reason: "io: NotFound".into()
                },
                Some(0)
            )
        );
    }

    #[test]
    fn approval_is_asked_only_after_the_pending_row_is_on_disk() {
        let mut e = env();
        let anchor = e._tmp.path().join("anchors").join("anchor.log");
        let mut lines_when_asked = None;
        let _ = execute_audited(&mut e.store, &e.sandbox, &write_action("a.txt"), || {
            lines_when_asked = Some(std::fs::read_to_string(&anchor).unwrap().lines().count());
            ApprovalDecision::Rejected
        })
        .unwrap();
        assert_eq!(
            lines_when_asked,
            Some(1),
            "pending row and its anchor first"
        );
    }

    #[test]
    fn report_maps_outcomes_to_documented_exit_codes() {
        let e = env();
        let act = write_action("a.txt");
        let code = |r| report(&e.sandbox, &act, r, "h");
        assert_eq!(code(Ok(Executed::Wrote(4))), EXIT_OK);
        assert_eq!(code(Ok(Executed::Listed(vec![]))), EXIT_OK);
        assert_eq!(
            code(Err(Refusal::Approval(ApprovalDecision::Rejected))),
            EXIT_REJECTED
        );
        assert_eq!(
            code(Err(Refusal::Approval(ApprovalDecision::AutoRejected))),
            EXIT_REJECTED
        );
        assert_eq!(
            code(Err(Refusal::Approval(ApprovalDecision::Timeout))),
            EXIT_TIMEOUT
        );
        assert_eq!(
            code(Err(Refusal::Kernel(KernelError::PathOutsideSandbox {
                path: "../x".into()
            }))),
            EXIT_REJECTED
        );
        assert_eq!(
            code(Err(Refusal::Kernel(KernelError::Io(
                std::io::Error::other("x")
            )))),
            EXIT_BAD_INPUT
        );
    }

    #[test]
    fn busy_log_has_its_own_exit_code() {
        assert_eq!(store_error_exit(&KernelError::AuditBusy), EXIT_BUSY);
        assert_eq!(
            store_error_exit(&KernelError::AuditCorrupted {
                sequence_no: 1,
                reason: "x".into()
            }),
            EXIT_AUDIT
        );
        assert_ne!(EXIT_BUSY, EXIT_AUDIT);
    }

    #[test]
    fn file_contents_shown_on_a_terminal_cannot_drive_it() {
        let shown = display_safe(b"linea 1\n\tcon tab \x1b]52;c;aGk=\x07 y \x1b[2J\xff fin");
        assert!(shown.contains("linea 1\n\tcon tab"), "{shown:?}");
        assert!(
            !shown.contains('\u{1b}') && !shown.contains('\u{7}'),
            "{shown:?}"
        );
        assert!(shown.contains("\\u{1b}"), "{shown:?}");
    }

    #[test]
    fn audit_args_keep_the_v1_shapes() {
        // Mismos bytes que antes de la fase 2: el args_hash de una acción
        // no cambia por el refactor.
        let json = |a: &Action| serde_json::to_string(&a.audit_args()).unwrap();
        assert_eq!(
            json(&write_action("a.txt")),
            r#"{"path":"a.txt","bytes":4}"#
        );
        assert_eq!(
            json(&Action::Read {
                path: "a.txt".into()
            }),
            r#"{"path":"a.txt"}"#
        );
        assert_eq!(
            json(&Action::List {
                path: String::new()
            }),
            r#"{"path":"."}"#
        );
    }

    #[test]
    fn proposals_are_parsed_into_actions() {
        let p = |v: serde_json::Value| parse_proposal(&v);
        assert!(matches!(
            p(serde_json::json!({"tool": "write_file", "args": {"path": "a", "content": "x"}})),
            Ok(Action::Write { .. })
        ));
        assert!(matches!(
            p(serde_json::json!({"tool": "read_file", "args": {"path": "a"}})),
            Ok(Action::Read { .. })
        ));
        assert!(matches!(
            p(serde_json::json!({"tool": "list_dir", "args": {"path": ""}})),
            Ok(Action::List { .. })
        ));
        for bad in [
            serde_json::json!({"tool": "write_file", "args": {"path": "a"}}),
            serde_json::json!({"tool": "read_file", "args": {}}),
            serde_json::json!({"tool": "read_file"}),
            serde_json::json!({"tool": "rm_rf", "args": {"path": "a"}}),
        ] {
            assert!(p(bad.clone()).is_err(), "{bad}");
        }
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
