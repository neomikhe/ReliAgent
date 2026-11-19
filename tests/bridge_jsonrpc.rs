//! Cross-process bridge integration tests.
//!
//! These spawn a real child process that speaks NDJSON JSON-RPC. We use
//! short inline Python snippets rather than the full `reliagent_python`
//! package so the test can run without the package being installed.
//!
//! The `full_sidecar` test that spawns the actual Python package is
//! marked `#[ignore]` and runs only with `cargo test -- --ignored`.

use std::path::{Path, PathBuf};

use reliagent::bridge::{Bridge, LlmBackend, SidecarSpec, rpc_codes};
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
    assert_eq!(proposal["args"]["path"], "notes/hi.txt");
    bridge.shutdown().expect("shutdown");
}
