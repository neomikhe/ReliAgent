//! Cross-process bridge integration tests.
//!
//! These spawn a real child process that speaks NDJSON JSON-RPC. We use
//! short inline Python snippets rather than the full `reliagent_python`
//! package so the test can run without the package being installed.
//!
//! The `full_sidecar` test that spawns the actual Python package is
//! marked `#[ignore]` and runs only with `cargo test -- --ignored`.

use std::path::{Path, PathBuf};

use std::time::{Duration, Instant};

use reliagent::bridge::{Bridge, BridgeLimits, LlmBackend, SidecarSpec, rpc_codes};
use reliagent::kernel::KernelError;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn python_cmd() -> String {
    // Caller may override with RELI_TEST_PYTHON when system `python`
    // doesn't resolve. Fall back to `python3` on unix-ish shells.
    std::env::var("RELI_TEST_PYTHON").unwrap_or_else(|_| {
        if cfg!(windows) {
            "python".into()
        } else {
            "python3".into()
        }
    })
}

fn spawn_inline(script: &str, cwd: &Path) -> Bridge {
    let cmd = vec![python_cmd(), "-c".into(), script.to_string()];
    Bridge::spawn(SidecarSpec::ExplicitCommand(cmd), cwd).expect("spawn python fake sidecar")
}

const ECHO_SERVER: &str = r#"
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        req = json.loads(line)
    except Exception as e:
        sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":None,"error":{"code":-32700,"message":f"parse: {e}"}})+"\n"); sys.stdout.flush(); continue
    method = req.get("method")
    rid = req.get("id")
    if method == "ping":
        resp = {"jsonrpc":"2.0","id":rid,"result":{"pong":True}}
    elif method == "boom":
        resp = {"jsonrpc":"2.0","id":rid,"error":{"code":-32000,"message":"boom"}}
    else:
        resp = {"jsonrpc":"2.0","id":rid,"error":{"code":-32601,"message":"method not found"}}
    sys.stdout.write(json.dumps(resp)+"\n"); sys.stdout.flush()
"#;

#[test]
fn ping_works_over_spawned_child() {
    let mut bridge = spawn_inline(ECHO_SERVER, &project_root());
    bridge.ping().expect("ping");
    bridge.shutdown().expect("clean shutdown");
}

#[test]
fn server_error_surfaces_as_bridge_error() {
    let mut bridge = spawn_inline(ECHO_SERVER, &project_root());
    // Use the low-level agent_run to trigger a method that returns an
    // RPC error object. agent.run is "method not found" in the fake.
    let err = bridge
        .agent_run("anything", LlmBackend::Mock)
        .expect_err("fake doesn't implement agent.run");
    assert!(format!("{err}").contains("method not found"), "{err}");
}

// Sidecar falso para agent.run: devuelve los params recibidos (en `reason`)
// o, si el prompt es "fail", un error de aplicación con `data`.
const AGENT_FAKE: &str = r#"
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    rid = req.get("id")
    params = req.get("params") or {}
    if params.get("prompt") == "fail":
        resp = {"jsonrpc":"2.0","id":rid,"error":{"code":-32011,"message":"model missing","data":{"kind":"model_missing","model":"m:1b"}}}
    else:
        resp = {"jsonrpc":"2.0","id":rid,"result":{"proposal":None,"verdict":"reject","reason":json.dumps(params, sort_keys=True)}}
    sys.stdout.write(json.dumps(resp)+"\n"); sys.stdout.flush()
"#;

#[test]
fn agent_run_sends_selected_backend() {
    for (backend, expected) in [(LlmBackend::Ollama, "ollama"), (LlmBackend::Mock, "mock")] {
        let mut bridge = spawn_inline(AGENT_FAKE, &project_root());
        let result = bridge.agent_run("hola", backend).expect("agent.run");
        let params: serde_json::Value = serde_json::from_str(&result.reason).unwrap();
        assert_eq!(params["backend"], expected);
        assert_eq!(params["prompt"], "hola");
        bridge.shutdown().expect("clean shutdown");
    }
}

#[test]
fn sidecar_rpc_error_keeps_code_and_data() {
    let mut bridge = spawn_inline(AGENT_FAKE, &project_root());
    let err = bridge
        .agent_run("fail", LlmBackend::Ollama)
        .expect_err("fake returns an RPC error");
    match err {
        KernelError::SidecarRpc { code, data, .. } => {
            assert_eq!(code, rpc_codes::MODEL_MISSING);
            assert_eq!(data.expect("data")["model"], "m:1b");
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

/// Los códigos de aplicación están duplicados en Rust y Python; esta prueba
/// impide que diverjan.
#[test]
fn rpc_codes_match_python_sidecar() {
    let main_py =
        std::fs::read_to_string(project_root().join("python-core/src/reliagent_python/main.py"))
            .expect("read main.py");
    let python_code = |name: &str| -> i64 {
        let prefix = format!("{name} = ");
        let line = main_py
            .lines()
            .find(|l| l.starts_with(&prefix))
            .unwrap_or_else(|| panic!("{name} not found in main.py"));
        line[prefix.len()..].trim().parse().expect("integer code")
    };
    assert_eq!(
        python_code("RPC_OLLAMA_UNREACHABLE"),
        rpc_codes::OLLAMA_UNREACHABLE
    );
    assert_eq!(python_code("RPC_MODEL_MISSING"), rpc_codes::MODEL_MISSING);
    assert_eq!(
        python_code("RPC_MODEL_INTEGRITY"),
        rpc_codes::MODEL_INTEGRITY
    );
    assert_eq!(python_code("RPC_LLM_ERROR"), rpc_codes::LLM_ERROR);
}

// --- Límites: un sidecar colgado o desbocado no puede bloquear `reli` ------

/// Lee las peticiones y nunca responde.
const SILENT_SERVER: &str = "import sys\nfor line in sys.stdin:\n    pass\n";

/// Responde con una "línea" sin fin.
const FLOOD_SERVER: &str = "import sys, time\nsys.stdin.readline()\nsys.stdout.write('x' * 5000)\nsys.stdout.flush()\ntime.sleep(10)\n";

fn spawn_limited(script: &str, limits: BridgeLimits) -> Bridge {
    let cmd = vec![python_cmd(), "-c".into(), script.to_string()];
    Bridge::spawn_with_limits(SidecarSpec::ExplicitCommand(cmd), &project_root(), limits)
        .expect("spawn python fake sidecar")
}

fn short(rpc_ms: u64, agent_ms: u64) -> BridgeLimits {
    BridgeLimits {
        rpc_timeout: Duration::from_millis(rpc_ms),
        agent_timeout: Duration::from_millis(agent_ms),
        ..BridgeLimits::default()
    }
}

/// Responde al ping y luego sigue vivo ignorando el EOF, con `then`.
fn answers_ping_then(then: &str) -> String {
    format!(
        r#"
import sys, json, time
req = json.loads(sys.stdin.readline())
sys.stdout.write(json.dumps({{'jsonrpc': '2.0', 'id': req['id'], 'result': {{'pong': True}}}}) + '\n')
sys.stdout.flush()
while True:
    {then}
"#
    )
}

/// `shutdown` en un hilo con plazo: si se colgara, la prueba falla en vez de
/// bloquear toda la suite.
fn shutdown_within(script: &str, grace_ms: u64) -> Result<(), KernelError> {
    let limits = BridgeLimits {
        shutdown_grace: Duration::from_millis(grace_ms),
        ..BridgeLimits::default()
    };
    let mut bridge = spawn_limited(script, limits);
    bridge.ping().expect("first answer is a pong");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(bridge.shutdown());
    });
    rx.recv_timeout(Duration::from_secs(10))
        .expect("shutdown() hung")
}

#[test]
fn shutdown_stops_a_sidecar_that_ignores_eof() {
    let err = shutdown_within(&answers_ping_then("time.sleep(1)"), 500)
        .expect_err("the sidecar had to be stopped");
    assert!(format!("{err}").contains("did not exit"), "{err}");
}

#[test]
fn shutdown_returns_promptly_while_the_sidecar_keeps_writing() {
    // Al dejar de leer, el hilo lector suelta el pipe: el sidecar muere por
    // broken pipe o se le detiene al cumplir el plazo. Lo que se prueba es
    // que shutdown vuelve (shutdown_within falla si se cuelga).
    let _ = shutdown_within(
        &answers_ping_then("sys.stdout.write('x' * 1000 + '\\n'); sys.stdout.flush()"),
        500,
    );
}

/// Ejecuta `f` en un hilo y falla la prueba si no vuelve en `secs`.
fn within<T: Send + 'static>(secs: u64, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(secs))
        .expect("the bridge call hung")
}

#[test]
fn writing_to_a_sidecar_that_never_reads_has_a_deadline() {
    // Una petición mayor que el buffer del pipe bloquea write_all si el hijo
    // no lee: también eso tiene que cumplir el plazo.
    const NEVER_READS: &str = "import time\nwhile True:\n    time.sleep(1)\n";
    let mut bridge = spawn_limited(NEVER_READS, short(60_000, 1_000));
    let prompt = "x".repeat(4 * 1024 * 1024);
    let start = Instant::now();
    let err = within(20, move || bridge.agent_run(&prompt, LlmBackend::Mock))
        .expect_err("the fake never reads nor answers");
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "{:?}",
        start.elapsed()
    );
    assert!(format!("{err}").contains("did not answer"), "{err}");
}

#[test]
fn bridge_is_unusable_after_a_timeout() {
    let mut bridge = spawn_limited(SILENT_SERVER, short(300, 300));
    let first = bridge.ping().expect_err("timeout");
    assert!(format!("{first}").contains("did not answer"), "{first}");
    // No un "closed stdout" engañoso: el motivo real sigue siendo el timeout.
    let second = bridge.ping().expect_err("the bridge is dead");
    assert!(format!("{second}").contains("did not answer"), "{second}");
}

#[test]
fn response_with_another_id_is_rejected() {
    const WRONG_ID: &str = r#"
import sys, json
for line in sys.stdin:
    req = json.loads(line)
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req["id"] + 1, "result": {"pong": True}}) + "\n")
    sys.stdout.flush()
"#;
    let mut bridge = spawn_limited(WRONG_ID, short(10_000, 10_000));
    let err = bridge.ping().expect_err("id does not match the request");
    assert!(format!("{err}").contains("id"), "{err}");
}

#[test]
fn huge_padded_proposal_passes_through_without_being_parsed() {
    // El resultado llega como texto (RawValue) hasta la CLI; el relleno no se
    // convierte en un árbol JSON en ningún punto del bridge.
    const PADDED: &str = r#"
import sys, json
req = json.loads(sys.stdin.readline())
proposal = {"tool": "write_file", "pad": [0] * 300000, "args": {"path": "a.txt", "content": "x"}}
result = {"proposal": proposal, "verdict": "reject", "reason": "", "agent_raw": "", "critic_stage": "llm", "trace": []}
sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": result}) + "\n")
sys.stdout.flush()
"#;
    let mut bridge = spawn_limited(PADDED, short(10_000, 10_000));
    let result = bridge
        .agent_run("hola", LlmBackend::Mock)
        .expect("agent.run");
    let raw = result.proposal.expect("proposal present");
    assert!(raw.get().len() > 300_000);
    assert!(
        raw.get().starts_with(r#"{"tool": "write_file""#),
        "{}",
        &raw.get()[..40]
    );
}

#[test]
fn unresponsive_sidecar_times_out_instead_of_hanging() {
    let mut bridge = spawn_limited(SILENT_SERVER, short(500, 60_000));
    let start = Instant::now();
    let err = bridge.ping().expect_err("the fake never answers");
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
    assert!(format!("{err}").contains("did not answer"), "{err}");
}

#[test]
fn agent_run_has_its_own_longer_timeout() {
    let mut bridge = spawn_limited(SILENT_SERVER, short(60_000, 500));
    let start = Instant::now();
    let err = bridge
        .agent_run("hola", LlmBackend::Mock)
        .expect_err("the fake never answers");
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
    assert!(format!("{err}").contains("did not answer"), "{err}");
    assert!(BridgeLimits::default().agent_timeout > BridgeLimits::default().rpc_timeout);
}

#[test]
fn endless_response_line_is_cut_off() {
    let limits = BridgeLimits {
        max_line_bytes: 1024,
        ..short(10_000, 10_000)
    };
    let mut bridge = spawn_limited(FLOOD_SERVER, limits);
    let start = Instant::now();
    let err = bridge.ping().expect_err("line exceeds the cap");
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
    assert!(format!("{err}").contains("too long"), "{err}");
}

#[test]
fn sidecar_closed_stdout_is_reported() {
    // Python that immediately exits without reading stdin.
    let script = "import sys; sys.exit(0)";
    let mut bridge = spawn_inline(script, &project_root());
    let err = bridge.ping().expect_err("child closed stdout");
    let msg = format!("{err}");
    assert!(
        msg.contains("closed stdout") || msg.contains("write request"),
        "unexpected error: {msg}"
    );
}

/// `reli` puede ejecutarse dentro de un directorio que no es de confianza.
/// Un `reliagent_python/` (o un `json.py`) en el cwd del sidecar no debe
/// sustituir al paquete instalado. (`-I` también ignora `PYTHONPATH`; no se
/// prueba aquí porque cambiar el entorno del proceso afectaría a las demás
/// pruebas, que corren en paralelo.)
/// Requiere el paquete instalado en el intérprete (venv): `--ignored`.
#[test]
#[ignore]
fn module_spec_does_not_import_from_cwd() {
    const IMPOSTOR: &str = r#"
import json, sys
for line in sys.stdin:
    req = json.loads(line)
    sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":req.get("id"),"result":{"pong":False}})+"\n"); sys.stdout.flush()
"#;
    let untrusted = tempfile::tempdir().expect("tempdir");
    let pkg = untrusted.path().join("reliagent_python");
    std::fs::create_dir(&pkg).unwrap();
    std::fs::write(pkg.join("__init__.py"), "").unwrap();
    std::fs::write(pkg.join("__main__.py"), IMPOSTOR).unwrap();

    let mut bridge = Bridge::spawn(
        SidecarSpec::Module {
            python: python_cmd().into(),
        },
        untrusted.path(),
    )
    .expect("spawn sidecar");
    bridge
        .ping()
        .expect("the installed sidecar must answer, not the impostor");
    bridge.shutdown().expect("shutdown");
}

/// End-to-end test against the real `reliagent_python` package. Requires
/// the package to be importable by `python -m reliagent_python`. Skipped
/// by default; run with `cargo test -- --ignored`.
#[test]
#[ignore]
fn full_python_sidecar_runs_agent() {
    let python_core = project_root().join("python-core");
    let spec =
        SidecarSpec::ExplicitCommand(vec![python_cmd(), "-m".into(), "reliagent_python".into()]);
    let mut bridge = Bridge::spawn(spec, &python_core).expect("spawn real sidecar");
    bridge.ping().expect("ping real sidecar");
    let result = bridge
        .agent_run("write 'hola' to notes/hi.txt", LlmBackend::Mock)
        .expect("agent.run");
    assert_eq!(result.verdict, "approve", "result={result:?}");
    let proposal = result.proposal.expect("proposal present");
    let proposal: serde_json::Value = serde_json::from_str(proposal.get()).unwrap();
    assert_eq!(proposal["args"]["path"], "notes/hi.txt");
    bridge.shutdown().expect("shutdown");
}
