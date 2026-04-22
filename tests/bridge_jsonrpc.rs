//! Cross-process bridge integration tests.
//!
//! These spawn a real child process that speaks NDJSON JSON-RPC. We use
//! short inline Python snippets rather than the full `reliagent_python`
//! package so the test can run without the package being installed.
//!
//! The `full_sidecar` test that spawns the actual Python package is
//! marked `#[ignore]` and runs only with `cargo test -- --ignored`.

use std::path::{Path, PathBuf};

use reliagent::bridge::{Bridge, SidecarSpec};

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
        .agent_run("anything")
        .expect_err("fake doesn't implement agent.run");
    assert!(format!("{err}").contains("method not found"), "{err}");
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
        .agent_run("write 'hola' to notes/hi.txt")
        .expect("agent.run");
    assert_eq!(result.verdict, "approve", "result={result:?}");
    let proposal = result.proposal.expect("proposal present");
    assert_eq!(proposal["args"]["path"], "notes/hi.txt");
    bridge.shutdown().expect("shutdown");
}
