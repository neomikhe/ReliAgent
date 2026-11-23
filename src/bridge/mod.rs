//! Python sidecar bridge.
//!
//! Spawns the Python orchestrator (`python -I -m reliagent_python`) as a child
//! process and speaks JSON-RPC 2.0 over stdin/stdout using NDJSON framing.
//! There is intentionally no async runtime here — the kernel is a simple
//! request/response consumer. One writer thread feeds the child's stdin and
//! one reader thread turns its stdout into lines (both through bounded
//! channels), so every call and the shutdown have a deadline
//! (`BridgeLimits`): a hung or runaway sidecar can neither block `reli`
//! forever nor make it buffer without limit. After a timeout or a broken
//! exchange the bridge is dead: the child is stopped and every later call
//! returns the original reason.
//!
//! The bridge does NOT execute tool calls proposed by the agent. The
//! kernel (Rust) remains the only executor; the bridge just carries the
//! proposal back across the wire.

pub mod jsonrpc;

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::kernel::{KernelError, KernelResult};

use jsonrpc::{RpcError, RpcRequest, RpcResponse};

/// Tope del `message` de un error JSON-RPC que se conserva.
const MAX_ERROR_MESSAGE_CHARS: usize = 1000;
/// `data` mayor que esto se descarta en vez de convertirlo en un árbol JSON.
const MAX_ERROR_DATA_BYTES: usize = 64 * 1024;

/// How the sidecar is invoked. `Module` uses `python -I -m reliagent_python`
/// (the normal path). `ExplicitCommand` is used by tests that need to
/// inject a fake sidecar binary.
#[derive(Debug, Clone)]
pub enum SidecarSpec {
    /// Run `<python> -I -m reliagent_python` (isolated mode). The caller supplies the
    /// interpreter path; we do not try to guess it.
    Module { python: std::path::PathBuf },
    /// Run an arbitrary command. First element is the program, rest are
    /// args. Used for testing with fake sidecars.
    ExplicitCommand(Vec<String>),
}

/// Which LLM the sidecar uses for `agent.run`. Serialised as the
/// `backend` param (`"ollama"` / `"mock"`). There is no default on the wire:
/// the caller always chooses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LlmBackend {
    /// Local Ollama daemon with the pinned, hash-verified model.
    Ollama,
    /// Deterministic pattern-matching agent (tests and offline demos).
    Mock,
}

/// Application error codes returned by the sidecar. Mirror of the
/// `RPC_*` constants in `python-core/src/reliagent_python/main.py`; the
/// `rpc_codes_match_python_sidecar` test keeps both in sync.
pub mod rpc_codes {
    /// Nothing listening on 127.0.0.1:11434.
    pub const OLLAMA_UNREACHABLE: i64 = -32010;
    /// Ollama lacks the pinned model tag. `data.model` names it.
    pub const MODEL_MISSING: i64 = -32011;
    /// The blob Ollama would use is not the pinned weights.
    pub const MODEL_INTEGRITY: i64 = -32012;
    /// Ollama failed during generation.
    pub const LLM_ERROR: i64 = -32013;
}

/// Result of one `agent.run` call. Mirrors the Python dataclass
/// `AgentRunResult.to_dict()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRunResult {
    /// Texto JSON validado pero sin convertir: la CLI lo lee a una
    /// estructura tipada (ver `parse_proposal`) y no construye un árbol de un
    /// tamaño que decida el sidecar o el modelo.
    pub proposal: Option<Box<serde_json::value::RawValue>>,
    pub verdict: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub agent_raw: String,
    #[serde(default)]
    pub critic_stage: String,
    #[serde(default)]
    pub trace: Vec<String>,
}

/// Límites de la comunicación con el sidecar.
#[derive(Debug, Clone, Copy)]
pub struct BridgeLimits {
    /// Respuesta de una llamada corta (`ping`).
    pub rpc_timeout: Duration,
    /// Respuesta de `agent.run`: verificar el modelo (~5 s) y dos
    /// inferencias, que en CPU pueden tardar minutos. El sidecar ya limita
    /// cada petición a Ollama (10 s / 600 s); esto es la red de seguridad.
    pub agent_timeout: Duration,
    /// Longitud máxima de una línea de respuesta (una propuesta lleva el
    /// contenido de `write_file`, hasta 10 MiB, escapado en JSON).
    pub max_line_bytes: usize,
    /// Cuánto espera `shutdown` a que el sidecar salga tras cerrar su
    /// stdin antes de matarlo.
    pub shutdown_grace: Duration,
}

impl Default for BridgeLimits {
    fn default() -> Self {
        Self {
            rpc_timeout: Duration::from_secs(30),
            agent_timeout: Duration::from_secs(25 * 60),
            max_line_bytes: 64 * 1024 * 1024,
            shutdown_grace: Duration::from_secs(5),
        }
    }
}

/// Handle to the Python sidecar. On drop, the child is killed and reaped
/// best-effort — prefer calling `shutdown()` for a clean exit.
pub struct Bridge {
    child: Child,
    /// Peticiones para el hilo escritor; soltarlo cierra el stdin del hijo.
    requests: Option<SyncSender<Vec<u8>>>,
    lines: Receiver<Result<String, String>>,
    next_id: AtomicU64,
    limits: BridgeLimits,
    /// Motivo por el que el bridge quedó inutilizable (ver `fail`).
    dead: Option<String>,
}

impl Bridge {
    /// Spawn the sidecar with the default `BridgeLimits`. `cwd` becomes the
    /// Python process's working directory (irrelevant to imports under `-I`).
    pub fn spawn(spec: SidecarSpec, cwd: &Path) -> KernelResult<Self> {
        Self::spawn_with_limits(spec, cwd, BridgeLimits::default())
    }

    pub fn spawn_with_limits(
        spec: SidecarSpec,
        cwd: &Path,
        limits: BridgeLimits,
    ) -> KernelResult<Self> {
        let mut cmd = match spec {
            SidecarSpec::Module { python } => {
                let mut c = Command::new(python);
                // -I (modo aislado): ni el cwd ni PYTHONPATH/PYTHON* ni el
                // site-packages del usuario entran en sys.path. Ejecutar
                // `reli` dentro de un directorio hostil no debe cargar su
                // código; el paquete tiene que estar instalado en el
                // intérprete elegido.
                c.arg("-I").arg("-m").arg("reliagent_python");
                c
            }
            SidecarSpec::ExplicitCommand(parts) => {
                if parts.is_empty() {
                    return Err(KernelError::Bridge("empty sidecar command".into()));
                }
                let mut c = Command::new(&parts[0]);
                c.args(&parts[1..]);
                c
            }
        };
        cmd.current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        let mut child = cmd
            .spawn()
            .map_err(|e| KernelError::Bridge(format!("spawn failed: {e}")))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| KernelError::Bridge("no stdin on child".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| KernelError::Bridge("no stdout on child".into()))?;

        // Canal acotado: si nadie consume, el hilo lector se detiene en vez
        // de acumular líneas (memoria máxima: unas pocas líneas).
        let (tx, lines) = mpsc::sync_channel(1);
        let max_line = limits.max_line_bytes;
        // El hilo termina solo: EOF del hijo, error, o `Bridge` soltado.
        std::thread::spawn(move || read_lines(stdout, max_line, tx));
        // Una petición en vuelo como mucho; termina al soltar `requests` o
        // cuando falla una escritura (hijo muerto).
        let (requests, pending) = mpsc::sync_channel(1);
        std::thread::spawn(move || write_requests(stdin, pending));

        Ok(Self {
            child,
            requests: Some(requests),
            lines,
            next_id: AtomicU64::new(1),
            limits,
            dead: None,
        })
    }

    fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Low-level JSON-RPC call. Sends one NDJSON request, reads one
    /// response. Errors if the sidecar returned a JSON-RPC error object.
    fn call<P: Serialize, R: for<'de> Deserialize<'de>>(
        &mut self,
        method: &str,
        params: &P,
        timeout: Duration,
    ) -> KernelResult<R> {
        if let Some(reason) = &self.dead {
            return Err(KernelError::Bridge(reason.clone()));
        }
        let id = self.next_id();
        let req = RpcRequest::new(id, method, params)
            .map_err(|e| KernelError::Bridge(format!("encode params: {e}")))?;
        let mut encoded = serde_json::to_vec(&req)
            .map_err(|e| KernelError::Bridge(format!("encode request: {e}")))?;
        encoded.push(b'\n');

        let line = self.exchange(method, encoded, timeout)?;
        let response: RpcResponse = match serde_json::from_str(line.trim()) {
            Ok(response) => response,
            Err(e) => {
                let preview: String = line.chars().take(200).collect();
                return Err(self.fail(format!("decode response: {e}: {preview:?}")));
            }
        };
        if !response.answers(id) {
            // Respuesta de otra petición: el flujo está desincronizado.
            let got = response.id.as_deref().map_or("none", RawValue::get);
            let got: String = got.chars().take(40).collect();
            return Err(self.fail(format!("sidecar answered with id {got} instead of {id}")));
        }
        if let Some(err) = response.error {
            return Err(rpc_error(err));
        }
        let result = response
            .result
            .ok_or_else(|| KernelError::Bridge("response had neither result nor error".into()))?;
        serde_json::from_str(result.get())
            .map_err(|e| KernelError::Bridge(format!("decode result: {e}")))
    }

    /// Entrega la petición al hilo escritor y espera una línea de respuesta,
    /// todo dentro de `timeout`.
    fn exchange(
        &mut self,
        method: &str,
        request: Vec<u8>,
        timeout: Duration,
    ) -> KernelResult<String> {
        let sent = match &self.requests {
            Some(requests) => requests.try_send(request),
            None => return Err(KernelError::Bridge("stdin already closed".into())),
        };
        match sent {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                return Err(self.fail("sidecar is not reading its stdin".into()));
            }
            Err(TrySendError::Disconnected(_)) => {
                return Err(self.fail("sidecar closed its stdin".into()));
            }
        }
        match self.lines.recv_timeout(timeout) {
            Ok(Ok(line)) => Ok(line),
            Ok(Err(reason)) => Err(self.fail(reason)),
            Err(RecvTimeoutError::Timeout) => Err(self.fail(format!(
                "sidecar did not answer `{method}` within {:.1} s (stopped it)",
                timeout.as_secs_f64()
            ))),
            Err(RecvTimeoutError::Disconnected) => Err(self.fail("sidecar closed stdout".into())),
        }
    }

    /// Deja el bridge inutilizable: detiene al hijo (el hilo escritor se
    /// desbloquea al fallar su escritura) y las llamadas siguientes devuelven
    /// este mismo motivo.
    fn fail(&mut self, reason: String) -> KernelError {
        let _ = self.child.kill();
        self.dead = Some(reason.clone());
        KernelError::Bridge(reason)
    }

    /// Liveness check. Returns Ok(()) if the sidecar answers.
    pub fn ping(&mut self) -> KernelResult<()> {
        #[derive(Deserialize)]
        struct Pong {
            pong: bool,
        }
        let r: Pong = self.call("ping", &serde_json::json!({}), self.limits.rpc_timeout)?;
        if r.pong {
            Ok(())
        } else {
            Err(KernelError::Bridge("ping returned pong=false".into()))
        }
    }

    /// Run the agent/critic loop for a single user prompt. The returned
    /// `AgentRunResult` is a *proposal* — the kernel still decides whether
    /// to execute.
    pub fn agent_run(&mut self, prompt: &str, backend: LlmBackend) -> KernelResult<AgentRunResult> {
        let params = serde_json::json!({ "prompt": prompt, "backend": backend });
        self.call("agent.run", &params, self.limits.agent_timeout)
    }

    /// Graceful shutdown: close stdin (triggering EOF in the Python loop),
    /// then wait for the child to exit.
    pub fn shutdown(mut self) -> KernelResult<()> {
        // Sin emisor, el hilo escritor termina y suelta el ChildStdin: el
        // pipe se cierra por nuestro lado.
        self.requests = None;
        // Dejar de consumir: el hilo lector termina en su siguiente envío.
        let (_, closed) = mpsc::sync_channel(0);
        drop(std::mem::replace(&mut self.lines, closed));
        let deadline = Instant::now() + self.limits.shutdown_grace;
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(()),
                Ok(Some(status)) => {
                    return Err(KernelError::Bridge(format!(
                        "sidecar exited with status {status}"
                    )));
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Ok(None) => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    return Err(KernelError::Bridge(format!(
                        "sidecar did not exit within {:.1} s after its stdin was closed (stopped it)",
                        self.limits.shutdown_grace.as_secs_f64()
                    )));
                }
                Err(e) => return Err(KernelError::Bridge(format!("wait failed: {e}"))),
            }
        }
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        // Best effort: close stdin first so a well-behaved sidecar exits
        // on its own, then kill if it didn't. We always wait() to avoid
        // leaving a zombie.
        self.requests = None;
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Error JSON-RPC del sidecar con tamaño acotado: `message` recortado y
/// `data` solo si es pequeño (la CLI lee de él un campo corto, `model`).
fn rpc_error(err: RpcError) -> KernelError {
    let data = err
        .data
        .filter(|d| d.get().len() <= MAX_ERROR_DATA_BYTES)
        .and_then(|d| serde_json::from_str(d.get()).ok());
    KernelError::SidecarRpc {
        code: err.code,
        message: err.message.chars().take(MAX_ERROR_MESSAGE_CHARS).collect(),
        data,
    }
}

/// Escribe las peticiones en el stdin del hijo. Si el hijo no lee, el que se
/// bloquea es este hilo y no `call`, que conserva su plazo; al detener al
/// hijo la escritura falla y el hilo termina.
fn write_requests(mut stdin: ChildStdin, pending: Receiver<Vec<u8>>) {
    for request in pending {
        if stdin
            .write_all(&request)
            .and_then(|()| stdin.flush())
            .is_err()
        {
            return;
        }
    }
}

/// Lee líneas NDJSON del hijo y las entrega por el canal. Una línea mayor que
/// `max_line` (o que no es UTF-8) corta la comunicación: el sidecar no puede
/// agotar la memoria de `reli`.
fn read_lines(stdout: ChildStdout, max_line: usize, tx: SyncSender<Result<String, String>>) {
    let mut reader = BufReader::new(stdout);
    let limit = max_line as u64 + 1;
    loop {
        let mut buf = Vec::new();
        let outcome = match (&mut reader).take(limit).read_until(b'\n', &mut buf) {
            Ok(0) => return,
            Ok(n) if n as u64 == limit && buf.last() != Some(&b'\n') => Err(format!(
                "sidecar response line too long (more than {max_line} bytes)"
            )),
            Ok(_) => String::from_utf8(buf).map_err(|_| "sidecar response is not UTF-8".into()),
            Err(e) => Err(format!("read response: {e}")),
        };
        let stop = outcome.is_err();
        if tx.send(outcome).is_err() || stop {
            return;
        }
    }
}
