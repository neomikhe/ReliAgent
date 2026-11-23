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

    /// Intérprete Python para el sidecar (con `reliagent_python` instalado).
    /// Por defecto: $RELI_PYTHON, el incluido en el release junto a `reli`,
    /// o python3/python del PATH.
    #[arg(long, global = true)]
    python: Option<PathBuf>,

    /// Directorio de trabajo del sidecar Python. Por defecto: el de `reli`.
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

/// Ruta lista para mostrar: saneada y sin el prefijo `\\?\` que añade
/// `canonicalize` en Windows (salvo en rutas UNC, donde forma parte de ella).
/// Solo afecta a lo que se imprime, nunca a la ruta que se usa.
fn shown_path(path: &Path) -> String {
    let text = path.display().to_string();
    let plain = match text.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC") => rest.to_string(),
        _ => text,
    };
    sanitize_for_terminal(&plain)
}

/// Directorio real del ejecutable `reli` (en un release, junto a `python/`).
/// Se resuelven los enlaces simbólicos: en macOS `current_exe` puede
/// devolver la ruta del enlace (p. ej. en /usr/local/bin).
fn exe_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let real = std::fs::canonicalize(&exe).unwrap_or(exe);
    real.parent().map(Path::to_path_buf)
}

/// Dónde estaría el intérprete de python-build-standalone incluido en el
/// release (`scripts/package_release.sh`).
fn bundled_python(exe_dir: &Path) -> PathBuf {
    if cfg!(windows) {
        exe_dir.join("python").join("python.exe")
    } else {
        exe_dir.join("python").join("bin").join("python3")
    }
}

/// De dónde salió el intérprete del sidecar (se muestra al usuario).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PythonSource {
    Flag,
    Env,
    Bundled,
    Path,
}

impl PythonSource {
    fn label(self) -> &'static str {
        match self {
            PythonSource::Flag => "--python",
            PythonSource::Env => "RELI_PYTHON",
            PythonSource::Bundled => "incluido junto a reli",
            PythonSource::Path => "PATH",
        }
    }
}

#[derive(Debug)]
struct PythonChoice {
    path: PathBuf,
    source: PythonSource,
    /// Por qué se descartó el intérprete incluido, si fue el caso.
    warning: Option<String>,
}

/// Intérprete del sidecar, por orden: `--python`, `RELI_PYTHON`, el incluido
/// junto al ejecutable (si `trust` lo acepta) y, por último, el del PATH. El
/// sidecar se lanza con `-I`, así que el elegido tiene que tener
/// `reliagent_python` instalado. Las rutas relativas se resuelven contra el
/// cwd de quien llama (`cwd`), igual en todas las plataformas.
fn resolve_python(
    flag: Option<PathBuf>,
    env: Option<std::ffi::OsString>,
    exe_dir: Option<&Path>,
    cwd: &Path,
    trust: impl Fn(&Path) -> Result<(), String>,
) -> PythonChoice {
    let absolute = |p: PathBuf| {
        // Un nombre sin separadores (p. ej. `python3.12`) se busca en el PATH.
        if p.is_relative() && p.components().count() > 1 {
            cwd.join(p)
        } else {
            p
        }
    };
    let choice = |path, source| PythonChoice {
        path,
        source,
        warning: None,
    };
    if let Some(p) = flag {
        return choice(absolute(p), PythonSource::Flag);
    }
    if let Some(p) = env.filter(|v| !v.is_empty()) {
        return choice(absolute(PathBuf::from(p)), PythonSource::Env);
    }
    let mut warning = None;
    if let Some(dir) = exe_dir {
        let bundled = bundled_python(dir);
        if bundled.is_file() {
            match trust(dir) {
                Ok(()) => return choice(bundled, PythonSource::Bundled),
                Err(why) => {
                    warning = Some(format!(
                        "se ignora el Python incluido en {}: {why}",
                        dir.join("python").display()
                    ))
                }
            }
        }
    }
    PythonChoice {
        path: PathBuf::from(if cfg!(windows) { "python" } else { "python3" }),
        source: PythonSource::Path,
        warning,
    }
}

/// (ruta, uid, mode) de un elemento del Python incluido.
#[cfg_attr(not(unix), allow(dead_code))]
type TrustEntry = (PathBuf, u32, u32);

/// Todos los `entries` deben ser del dueño de `reli` (o de root) y no
/// escribibles por grupo u otros: si no, otra cuenta pudo dejar ahí un
/// intérprete o un módulo que `reli` ejecutaría. El error nombra el elemento
/// para que el usuario pueda corregirlo.
#[cfg_attr(not(unix), allow(dead_code))]
fn check_owner_and_mode(entries: &[TrustEntry], owner: u32) -> Result<(), String> {
    for (path, uid, mode) in entries {
        if *uid != owner && *uid != 0 {
            return Err(format!(
                "{} is owned by uid {uid}, not by the owner of reli",
                path.display()
            ));
        }
        if mode & 0o022 != 0 {
            return Err(format!(
                "{} is writable by group or others (mode {:o})",
                path.display(),
                mode & 0o777
            ));
        }
    }
    Ok(())
}

/// Comprueba el `python/` incluido antes de confiar en él, frente al dueño
/// del ejecutable de `reli` (ver `bundle_entries`). En Windows las ACL no se
/// comprueban: el directorio del release forma parte de la base de
/// confianza (ver docs/THREAT_MODEL.md).
#[cfg(unix)]
fn check_bundle_trust(exe_dir: &Path) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let (_, owner, _) = unix_meta(&exe, true)?;
    check_owner_and_mode(&bundle_entries(exe_dir)?, owner)
}

/// (ruta, uid, mode) de `p`, siguiendo o no un enlace simbólico final.
#[cfg(unix)]
fn unix_meta(p: &Path, follow: bool) -> Result<TrustEntry, String> {
    use std::os::unix::fs::MetadataExt;
    let m = if follow {
        std::fs::metadata(p)
    } else {
        std::fs::symlink_metadata(p)
    };
    m.map(|m| (p.to_path_buf(), m.uid(), m.mode()))
        .map_err(|e| format!("{}: {e}", p.display()))
}

/// Lo que se comprueba del Python incluido: la cadena de directorios hasta
/// el intérprete, todos los directorios de `lib/python3.*` (site-packages
/// incluido), el intérprete real (enlaces resueltos) y todo el paquete
/// `reliagent_python`. Los archivos de la biblioteca estándar no se miran
/// uno a uno (son miles); sus directorios sí, así que nadie más puede
/// añadir ni sustituir módulos.
#[cfg(unix)]
fn bundle_entries(exe_dir: &Path) -> Result<Vec<TrustEntry>, String> {
    let python_dir = exe_dir.join("python");
    let lib = python_dir.join("lib");
    let interpreter = std::fs::canonicalize(bundled_python(exe_dir))
        .map_err(|e| format!("{}: {e}", bundled_python(exe_dir).display()))?;
    let mut entries = Vec::new();
    for dir in [&python_dir, &python_dir.join("bin"), &lib] {
        entries.push(unix_meta(dir, false)?);
    }
    entries.push(unix_meta(&interpreter, true)?);
    let mut found = false;
    for stdlib in python_version_dirs(&lib)? {
        // Todos los directorios (site-packages incluido), sin los archivos.
        dir_tree_entries(&stdlib, &mut entries)?;
        let package = stdlib.join("site-packages").join("reliagent_python");
        if package.exists() {
            tree_entries(&package, &mut entries)?;
            found = true;
        }
    }
    if !found {
        return Err(format!(
            "reliagent_python is not installed under {}",
            lib.display()
        ));
    }
    Ok(entries)
}

/// Los `lib/python3.*` del runtime (normalmente uno).
#[cfg(unix)]
fn python_version_dirs(lib: &Path) -> Result<Vec<PathBuf>, String> {
    let entries = std::fs::read_dir(lib).map_err(|e| format!("{}: {e}", lib.display()))?;
    Ok(entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|p| p.is_dir())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("python3."))
        })
        .collect())
}

/// (uid, mode) de `dir` y de todos sus subdirectorios; los archivos no se
/// examinan (el tipo sale de la entrada del directorio, sin `stat`).
#[cfg(unix)]
fn dir_tree_entries(dir: &Path, out: &mut Vec<TrustEntry>) -> Result<(), String> {
    out.push(unix_meta(dir, false)?);
    let fail = |e: std::io::Error| format!("{}: {e}", dir.display());
    for child in std::fs::read_dir(dir).map_err(fail)? {
        let child = child.map_err(fail)?;
        if child.file_type().map_err(fail)?.is_dir() {
            dir_tree_entries(&child.path(), out)?;
        }
    }
    Ok(())
}

/// (uid, mode) de `root` y de todo lo que contiene. Un enlace simbólico
/// dentro del paquete es un error: podría apuntar fuera de lo comprobado.
#[cfg(unix)]
fn tree_entries(root: &Path, out: &mut Vec<TrustEntry>) -> Result<(), String> {
    let kind = std::fs::symlink_metadata(root)
        .map_err(|e| format!("{}: {e}", root.display()))?
        .file_type();
    if kind.is_symlink() {
        return Err(format!(
            "{}: symbolic link inside the bundled sidecar",
            root.display()
        ));
    }
    out.push(unix_meta(root, false)?);
    if kind.is_dir() {
        let children = std::fs::read_dir(root).map_err(|e| format!("{}: {e}", root.display()))?;
        for child in children {
            let child = child.map_err(|e| format!("{}: {e}", root.display()))?;
            tree_entries(&child.path(), out)?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_bundle_trust(_exe_dir: &Path) -> Result<(), String> {
    Ok(())
}

/// Directorio de trabajo del sidecar. Con `-I` no afecta a las
/// importaciones; solo tiene que existir.
fn default_sidecar_cwd(exe_dir: Option<&Path>) -> PathBuf {
    exe_dir
        .map(Path::to_path_buf)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(std::env::temp_dir)
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
    let exe_dir = exe_dir();
    let caller_cwd = std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir());
    let python = resolve_python(
        cli.python,
        std::env::var_os("RELI_PYTHON"),
        exe_dir.as_deref(),
        &caller_cwd,
        check_bundle_trust,
    );
    let python_cwd = cli
        .python_cwd
        .unwrap_or_else(|| default_sidecar_cwd(exe_dir.as_deref()));
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

fn spawn_bridge(python: &PythonChoice, python_cwd: &Path) -> Result<Bridge, i32> {
    if let Some(warning) = &python.warning {
        eprintln!("[reli] aviso: {}", sanitize_for_terminal(warning));
    }
    // Qué intérprete corre el sidecar, y por qué: p. ej. un RELI_PYTHON
    // olvidado gana al Python incluido en el release.
    eprintln!(
        "[reli] sidecar: {} ({})",
        shown_path(&python.path),
        python.source.label()
    );
    let python = &python.path;
    let spec = SidecarSpec::Module {
        python: python.to_path_buf(),
    };
    Bridge::spawn(spec, python_cwd).map_err(|e| {
        eprintln!(
            "[reli] no se pudo lanzar el sidecar Python ({}): {}",
            shown_path(python),
            error_text(&e)
        );
        eprintln!("{}", SIDECAR_SETUP_HINT);
        EXIT_BRIDGE
    })
}

/// Cómo dar a `reli` un intérprete con el sidecar instalado.
const SIDECAR_SETUP_HINT: &str = "[reli] el sidecar necesita un Python 3.12+ con el paquete `reliagent_python` instalado:\n\
     [reli]   - release: usa el `python/` incluido junto a `reli` (no lo muevas por separado);\n\
     [reli]   - desde el código: `uv sync` en python-core/ y luego\n\
     [reli]     RELI_PYTHON=python-core/.venv/bin/python (Windows: python-core\\.venv\\Scripts\\python.exe)\n\
     [reli]     o `--python <ruta>`.";

fn run_ping(python: &PythonChoice, python_cwd: &Path) -> i32 {
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
            if let Some(hint) = sidecar_hint(&e) {
                eprintln!("{hint}");
            }
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
    shown(&e.to_string(), &[])
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
    // El hijo murió antes de responder: casi siempre, un intérprete sin
    // `reliagent_python` (con -I no lo busca en el directorio actual).
    if matches!(err, KernelError::Bridge(m) if m.contains("closed stdout")) {
        return Some(SIDECAR_SETUP_HINT.to_string());
    }
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
    python: &PythonChoice,
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
    let summary = render_proposal_summary(&action, &result.verdict, &result.critic_stage);
    let mode = approval_mode(non_interactive);
    run_action(sandbox_path, audit_dir, &action, || {
        approval::request_approval(&summary, mode)
    })
}

/// Máximo de caracteres de texto del agente que se muestra por línea: lo que
/// devuelva el modelo (o quien suplante a Ollama) no debe inundar la
/// terminal.
const MAX_SHOWN_CHARS: usize = 2000;

/// Recorta `s` a `MAX_SHOWN_CHARS` caracteres, indicando cuánto se omitió.
fn clip(s: &str) -> String {
    match s.char_indices().nth(MAX_SHOWN_CHARS) {
        None => s.to_string(),
        Some((cut, _)) => format!("{}… ({} bytes más)", &s[..cut], s.len() - cut),
    }
}

/// Líneas a mostrar del resultado del agente, ya saneadas y recortadas.
fn agent_result_lines(result: &AgentRunResult) -> Vec<String> {
    let shown = |label: &str, text: &str| format!("[reli] {label}: {}", shown(text, &[]));
    let mut lines = vec![shown("agente: verdict", &result.verdict)];
    if !result.critic_stage.is_empty() {
        lines.push(shown("crítico: stage", &result.critic_stage));
    }
    if !result.reason.is_empty() {
        lines.push(shown("motivo", &result.reason));
    }
    if let Some(p) = &result.proposal {
        lines.push(shown("propuesta", p.get()));
    }
    for t in result.trace.iter().take(20) {
        lines.push(shown("trace", t));
    }
    lines
}

/// Texto externo listo para la terminal: primero se escapa (puede crecer
/// hasta 6 veces) y después se recorta, para que el tope sea real.
fn shown(text: &str, keep: &[char]) -> String {
    clip(&escape_unsafe_chars(text, keep))
}

/// Lo que ve el humano antes de aprobar: la acción ya interpretada (la misma
/// que se ejecutará), con el contenido recortado y su tamaño real.
fn render_proposal_summary(action: &Action, verdict: &str, stage: &str) -> String {
    let mut out = format!(
        "[reli] propuesta a ejecutar\n  tool: {}\n  path: {}",
        action.tool(),
        shown(action.path(), &[])
    );
    if let Action::Write { content, .. } = action {
        // Saltos de línea conservados para que el contenido se pueda leer.
        out.push_str(&format!(
            "\n  content ({} bytes):\n{}",
            content.len(),
            shown(content, &['\n'])
        ));
    }
    out.push_str(&format!(
        "\n  critic: {} ({})",
        shown(verdict, &[]),
        shown(stage, &[])
    ));
    out
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

/// Forma de la propuesta en el cable. Solo los campos que se usan; serde
/// salta los demás sin construirlos (no hay árbol JSON en memoria).
#[derive(serde::Deserialize)]
struct WireProposal {
    tool: Option<String>,
    args: Option<WireArgs>,
}

#[derive(serde::Deserialize)]
struct WireArgs {
    path: Option<String>,
    content: Option<String>,
}

/// Convierte la propuesta del sidecar en una `Action`. No ejecuta nada.
fn parse_proposal(proposal: &serde_json::value::RawValue) -> Result<Action, String> {
    let wire: WireProposal =
        serde_json::from_str(proposal.get()).map_err(|e| format!("propuesta mal formada: {e}"))?;
    let args = wire.args.ok_or("propuesta sin args")?;
    let path = args.path.ok_or("propuesta sin args.path")?;
    match wire.tool.as_deref().unwrap_or("") {
        "write_file" => {
            let content = args
                .content
                .ok_or("propuesta write_file sin args.content")?;
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
            proposal: Some(raw(
                &serde_json::json!({"tool": null, "reason": HOSTILE}).to_string()
            )),
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
        let action = Action::Write {
            path: HOSTILE.into(),
            content: HOSTILE.into(),
        };
        let summary = render_proposal_summary(&action, HOSTILE, HOSTILE);
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

    fn raw(json: &str) -> Box<serde_json::value::RawValue> {
        serde_json::value::RawValue::from_string(json.to_string()).unwrap()
    }

    #[test]
    fn proposals_are_parsed_into_actions() {
        let p = |json: &str| parse_proposal(&raw(json));
        assert!(matches!(
            p(r#"{"tool": "write_file", "args": {"path": "a", "content": "x"}}"#),
            Ok(Action::Write { .. })
        ));
        assert!(matches!(
            p(r#"{"tool": "read_file", "args": {"path": "a"}}"#),
            Ok(Action::Read { .. })
        ));
        assert!(matches!(
            p(r#"{"tool": "list_dir", "args": {"path": ""}}"#),
            Ok(Action::List { .. })
        ));
        for bad in [
            r#"{"tool": "write_file", "args": {"path": "a"}}"#,
            r#"{"tool": "read_file", "args": {}}"#,
            r#"{"tool": "read_file"}"#,
            r#"{"tool": "rm_rf", "args": {"path": "a"}}"#,
            r#"{"tool": "read_file", "args": {"path": ["a"]}}"#,
            r#"[1, 2]"#,
        ] {
            assert!(p(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn unknown_proposal_fields_are_skipped_not_built() {
        // Un relleno enorme (p. ej. de un servidor que suplanta a Ollama) se
        // salta al leer; no se construye un árbol JSON en memoria.
        let pad = vec!["0"; 200_000].join(",");
        let json = format!(
            r#"{{"tool": "write_file", "pad": [{pad}], "args": {{"path": "a", "content": "x", "pad": [{pad}]}}}}"#
        );
        assert!(matches!(p_ok(&json), Action::Write { .. }));
    }

    fn p_ok(json: &str) -> Action {
        parse_proposal(&raw(json)).expect("valid proposal")
    }

    #[test]
    fn displayed_agent_output_is_clipped() {
        let big = "x".repeat(50_000);
        let result = AgentRunResult {
            proposal: Some(raw(&format!(r#"{{"tool": null, "reason": "{big}"}}"#))),
            verdict: "reject".into(),
            reason: big.clone(),
            agent_raw: big.clone(),
            critic_stage: "deterministic".into(),
            trace: vec![big.clone()],
        };
        for line in agent_result_lines(&result) {
            assert!(
                line.chars().count() < MAX_SHOWN_CHARS + 100,
                "{} chars",
                line.len()
            );
        }
    }

    #[test]
    fn approval_summary_shows_path_and_bounded_content() {
        let content = "línea\n".repeat(5_000);
        let action = Action::Write {
            path: "notas/a.txt".into(),
            content: content.clone(),
        };
        let summary = render_proposal_summary(&action, "approve", "ok");
        assert!(summary.contains("notas/a.txt"), "{summary}");
        assert!(summary.contains(&content.len().to_string()), "{summary}");
        assert!(summary.chars().count() < MAX_SHOWN_CHARS + 400);
        summary.lines().for_each(assert_terminal_safe);
    }

    // --- Intérprete del sidecar --------------------------------------------

    /// Simula una instalación de release: `<dir>/python/...` junto a `reli`.
    fn release_dir_with_bundled_python() -> TempDir {
        let tmp = TempDir::new().unwrap();
        let py = bundled_python(tmp.path());
        std::fs::create_dir_all(py.parent().unwrap()).unwrap();
        std::fs::write(&py, b"").unwrap();
        tmp
    }

    fn trusted(_: &Path) -> Result<(), String> {
        Ok(())
    }

    fn resolve(flag: Option<&str>, env: Option<&str>, exe_dir: Option<&Path>) -> PythonChoice {
        resolve_python(
            flag.map(PathBuf::from),
            env.map(Into::into),
            exe_dir,
            Path::new("/caller/cwd"),
            trusted,
        )
    }

    #[test]
    fn explicit_python_flag_wins() {
        let release = release_dir_with_bundled_python();
        let abs = std::env::temp_dir().join("py").join("python3");
        let chosen = resolve(abs.to_str(), Some("/env/python"), Some(release.path()));
        assert_eq!(chosen.path, abs);
        assert_eq!(chosen.source, PythonSource::Flag);
    }

    #[test]
    fn reli_python_env_wins_over_the_bundled_interpreter() {
        let release = release_dir_with_bundled_python();
        let abs = std::env::temp_dir().join("env").join("python");
        let chosen = resolve(None, abs.to_str(), Some(release.path()));
        assert_eq!(chosen.path, abs);
        assert_eq!(chosen.source, PythonSource::Env);
    }

    #[test]
    fn bundled_interpreter_next_to_the_binary_is_used() {
        let release = release_dir_with_bundled_python();
        let chosen = resolve(None, None, Some(release.path()));
        assert_eq!(chosen.path, bundled_python(release.path()));
        assert_eq!(chosen.source, PythonSource::Bundled);
        let expected_tail = if cfg!(windows) {
            Path::new("python").join("python.exe")
        } else {
            Path::new("python").join("bin").join("python3")
        };
        assert!(chosen.path.ends_with(expected_tail));
    }

    #[test]
    fn falls_back_to_the_path_interpreter() {
        let empty = TempDir::new().unwrap();
        let fallback = PathBuf::from(if cfg!(windows) { "python" } else { "python3" });
        let chosen = resolve(None, None, Some(empty.path()));
        assert_eq!(
            (chosen.path, chosen.source),
            (fallback.clone(), PythonSource::Path)
        );
        assert_eq!(resolve(None, Some(""), None).path, fallback);
    }

    #[test]
    fn relative_interpreter_paths_are_resolved_against_the_callers_cwd() {
        // Sin esto, Unix los resolvía contra el cwd del hijo (el directorio
        // de reli) y Windows contra el del padre.
        let rel = Path::new("venv").join("bin").join("python");
        let chosen = resolve(rel.to_str(), None, None);
        assert_eq!(chosen.path, Path::new("/caller/cwd").join(&rel));
        // Un nombre sin separadores se busca en el PATH: se deja igual.
        assert_eq!(
            resolve(Some("python3.12"), None, None).path,
            PathBuf::from("python3.12")
        );
    }

    #[test]
    fn untrusted_bundled_interpreter_is_skipped_with_a_warning() {
        let release = release_dir_with_bundled_python();
        let chosen = resolve_python(None, None, Some(release.path()), Path::new("/c"), |_| {
            Err("python/ is writable by others".into())
        });
        assert_eq!(chosen.source, PythonSource::Path);
        let warning = chosen.warning.expect("the user must be told");
        assert!(warning.contains("writable by others"), "{warning}");
    }

    #[test]
    fn verbatim_windows_prefix_is_hidden_when_shown() {
        assert_eq!(
            shown_path(Path::new(r"\\?\C:\rel\python\python.exe")),
            r"C:\rel\python\python.exe"
        );
        // UNC y rutas normales, sin cambios.
        assert_eq!(
            shown_path(Path::new(r"\\?\UNC\srv\share\p.exe")),
            r"\\?\UNC\srv\share\p.exe"
        );
        assert_eq!(
            shown_path(Path::new("/opt/reli/python/bin/python3")),
            "/opt/reli/python/bin/python3"
        );
    }

    #[test]
    fn bundle_trust_requires_same_owner_and_no_foreign_write_access() {
        let owner = 1000;
        let check =
            |uid, mode| check_owner_and_mode(&[(PathBuf::from("python/bin"), uid, mode)], owner);
        assert!(
            check_owner_and_mode(
                &[
                    (PathBuf::from("python"), 1000, 0o40755),
                    (PathBuf::from("python/bin/python3"), 1000, 0o100755)
                ],
                owner
            )
            .is_ok()
        );
        assert!(check(0, 0o40755).is_ok(), "root may own it");
        assert!(check(1001, 0o40755).is_err());
        assert!(check(1000, 0o40775).is_err(), "group-writable");
        assert!(check(1000, 0o40757).is_err(), "world-writable");
        // El error nombra el elemento culpable.
        assert!(check(1000, 0o40775).unwrap_err().contains("python/bin"));
        assert!(check(1001, 0o40755).unwrap_err().contains("python/bin"));
    }

    /// Árbol mínimo con la forma del release en Unix, con modos 755/644.
    #[cfg(unix)]
    fn fake_unix_bundle() -> (TempDir, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("rel");
        let pkg = root.join("python/lib/python3.12/site-packages/reliagent_python");
        std::fs::create_dir_all(pkg.join("prompts")).unwrap();
        std::fs::create_dir_all(root.join("python/lib/python3.12/json")).unwrap();
        std::fs::create_dir_all(root.join("python/bin")).unwrap();
        std::fs::write(root.join("python/bin/python3.12"), "").unwrap();
        std::os::unix::fs::symlink("python3.12", root.join("python/bin/python3")).unwrap();
        std::fs::write(pkg.join("main.py"), "").unwrap();
        std::fs::write(pkg.join("prompts/system_agent.md"), "").unwrap();
        for entry in walk(&root) {
            let mode = if entry.is_dir() { 0o755 } else { 0o644 };
            if !entry.is_symlink() {
                std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(mode)).unwrap();
            }
        }
        (tmp, root)
    }

    #[cfg(unix)]
    fn walk(dir: &Path) -> Vec<PathBuf> {
        let mut out = vec![dir.to_path_buf()];
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() && !path.is_symlink() {
                out.extend(walk(&path));
            } else {
                out.push(path);
            }
        }
        out
    }

    #[cfg(unix)]
    #[test]
    fn bundle_trust_covers_site_packages_and_the_sidecar_package() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let check = |root: &Path| {
            let owner = std::fs::metadata(root).unwrap().uid();
            bundle_entries(root).and_then(|e| check_owner_and_mode(&e, owner))
        };
        let set = |p: PathBuf, mode| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap()
        };
        let site = "python/lib/python3.12/site-packages";

        let (_tmp, root) = fake_unix_bundle();
        assert_eq!(check(&root), Ok(()));

        set(root.join(site), 0o777);
        assert!(
            check(&root).unwrap_err().contains("writable"),
            "site-packages"
        );
        set(root.join(site), 0o755);

        let stdlib_subdir = root.join("python/lib/python3.12/json");
        set(stdlib_subdir.clone(), 0o775);
        assert!(
            check(&root).unwrap_err().contains("writable"),
            "stdlib subdir"
        );
        set(stdlib_subdir, 0o755);

        let prompt = root
            .join(site)
            .join("reliagent_python/prompts/system_agent.md");
        set(prompt.clone(), 0o666);
        assert!(
            check(&root).unwrap_err().contains("writable"),
            "file in the package"
        );
        set(prompt.clone(), 0o644);

        std::fs::remove_file(&prompt).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", &prompt).unwrap();
        assert!(check(&root).unwrap_err().contains("symbolic link"));
        std::fs::remove_file(&prompt).unwrap();

        std::fs::remove_dir_all(root.join(site).join("reliagent_python")).unwrap();
        assert!(check(&root).unwrap_err().contains("not installed"));
    }

    #[test]
    fn sidecar_working_directory_is_never_a_relative_python_core() {
        // Antes era ./python-core: no existe fuera del repo y, sin -I, era
        // una vía para cargar código del directorio actual.
        let release = TempDir::new().unwrap();
        assert_eq!(default_sidecar_cwd(Some(release.path())), release.path());
        let fallback = default_sidecar_cwd(None);
        assert!(
            fallback.is_absolute() && fallback.is_dir(),
            "{}",
            fallback.display()
        );
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

    #[test]
    fn sidecar_that_died_on_start_gets_the_setup_hint() {
        let hint = sidecar_hint(&KernelError::Bridge("sidecar closed stdout".into())).unwrap();
        assert!(
            hint.contains("RELI_PYTHON") && hint.contains("--python"),
            "{hint}"
        );
    }
}
