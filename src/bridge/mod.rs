//! Python sidecar bridge.
//!
//! Spawns the Python orchestrator (`python -I -m reliagent_python`) as a child
//! process and speaks JSON-RPC 2.0 over stdin/stdout using NDJSON framing.
//! There is intentionally no async runtime here — the kernel is a simple
//! request/response consumer and blocking I/O keeps the implementation
//! auditable.
//!
//! The bridge does NOT execute tool calls proposed by the agent. The
//! kernel (Rust) remains the only executor; the bridge just carries the
//! proposal back across the wire.

pub mod jsonrpc;

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::kernel::{KernelError, KernelResult};

use jsonrpc::{RpcRequest, RpcResponse};

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
    pub proposal: Option<serde_json::Value>,
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

/// Handle to the Python sidecar. On drop, the child is killed and reaped
/// best-effort — prefer calling `shutdown()` for a clean exit.
pub struct Bridge {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_id: AtomicU64,
}

impl Bridge {
    /// Spawn the sidecar. `cwd` is typically the repo root; it becomes the
    /// Python process's working directory so relative imports resolve.
    pub fn spawn(spec: SidecarSpec, cwd: &Path) -> KernelResult<Self> {
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

        Ok(Self {
            child,
            stdin: Some(stdin),
            stdout: BufReader::new(stdout),
            next_id: AtomicU64::new(1),
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
    ) -> KernelResult<R> {
        let id = self.next_id();
        let req = RpcRequest::new(id, method, params)
            .map_err(|e| KernelError::Bridge(format!("encode params: {e}")))?;
        let encoded = serde_json::to_string(&req)
            .map_err(|e| KernelError::Bridge(format!("encode request: {e}")))?;

        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| KernelError::Bridge("stdin already closed".into()))?;
        stdin
            .write_all(encoded.as_bytes())
            .and_then(|_| stdin.write_all(b"\n"))
            .and_then(|_| stdin.flush())
            .map_err(|e| KernelError::Bridge(format!("write request: {e}")))?;

        let mut line = String::new();
        let n = self
            .stdout
            .read_line(&mut line)
            .map_err(|e| KernelError::Bridge(format!("read response: {e}")))?;
        if n == 0 {
            return Err(KernelError::Bridge("sidecar closed stdout".into()));
        }

        let response: RpcResponse = serde_json::from_str(line.trim())
            .map_err(|e| KernelError::Bridge(format!("decode response: {e}: {line:?}")))?;
        if let Some(err) = response.error {
            return Err(KernelError::SidecarRpc {
                code: err.code,
                message: err.message,
                data: err.data,
            });
        }
        let result = response
            .result
            .ok_or_else(|| KernelError::Bridge("response had neither result nor error".into()))?;
        serde_json::from_value(result)
            .map_err(|e| KernelError::Bridge(format!("decode result: {e}")))
    }

    /// Liveness check. Returns Ok(()) if the sidecar answers.
    pub fn ping(&mut self) -> KernelResult<()> {
        #[derive(Deserialize)]
        struct Pong {
            pong: bool,
        }
        let r: Pong = self.call("ping", &serde_json::json!({}))?;
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
        self.call("agent.run", &params)
    }

    /// Graceful shutdown: close stdin (triggering EOF in the Python loop),
    /// then wait for the child to exit.
    pub fn shutdown(mut self) -> KernelResult<()> {
        // Dropping the ChildStdin closes the pipe from our side.
        self.stdin = None;
        match self.child.wait() {
            Ok(status) if status.success() => Ok(()),
            Ok(status) => Err(KernelError::Bridge(format!(
                "sidecar exited with status {status}"
            ))),
            Err(e) => Err(KernelError::Bridge(format!("wait failed: {e}"))),
        }
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        // Best effort: close stdin first so a well-behaved sidecar exits
        // on its own, then kill if it didn't. We always wait() to avoid
        // leaving a zombie.
        self.stdin = None;
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
