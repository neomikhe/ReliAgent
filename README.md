# ReliAgent

> A local trusted kernel for AI agents. Every action a model proposes is
> filtered through a deterministic policy engine in Rust, gated by human
> approval, and recorded in a tamper-evident HMAC-chained audit log — all
> 100% offline.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
![status](https://img.shields.io/badge/status-research%20preview-orange)
![platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey)

---

## What this is

ReliAgent is a **CLI-first research preview** of a different way to run
local AI agents. Instead of trusting the LLM with direct filesystem access
(the usual LangChain / AutoGPT / CrewAI pattern), ReliAgent puts a small
Rust kernel between the model and the OS:

- The model *proposes* a tool call.
- A deterministic Rust policy engine validates it. If the engine says
  no, the engine wins. The LLM critic can only *also* say no — it cannot
  overrule a rejection.
- A TTY prompt asks the human. Timeout or no TTY → default reject.
- On approval, the action runs inside a `cap-std` sandbox capability.
- The full before/after is written to an HMAC-chained audit log, signed
  with a key stored in the OS keyring. Tampering is detectable with
  `reli verify`.

**What this is not.** It is not blockchain, not "provably secure", not a
production-ready agent framework. It is a Research Preview focused on one
question: *can we make local agents auditable and reversible by default,
with no cloud and no magic?*

For the threat model and what is explicitly **out of scope**, read
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) before relying on anything
here.

---

## Why

Current local-agent stacks share a bad habit: when the LLM hallucinates
`rm -rf /`, the shell runs it. When it's prompt-injected by a file it just
read, nothing in the stack notices. ReliAgent's answer:

1. **Determinism before intelligence.** Hard rules in Rust (path jail,
   size cap, TTY gate) run *before* any LLM heuristic.
2. **Tamper-evidence by default.** Every action — approved or rejected —
   is HMAC-chained. A passive attacker with disk access can read the log
   but can't forge entries without the keyring key.
3. **No network.** The binary makes zero outbound calls. The Python
   sidecar only talks to `localhost:11434` (Ollama). Model download is
   an explicit, one-shot, signed operation.

If those tradeoffs match how you want local agents to behave, this is for
you. If you need cloud-scale orchestration or production SLAs, this is
not that.

---

## Status: Research Preview (v0.1.0)

| Area | Status |
|---|---|
| Rust kernel (policy engine, sandbox, HMAC chain) | Implemented, ~90 unit tests + property tests. |
| CLI (`reli run / verify / sandbox / reset`) | Implemented. |
| Python sidecar (orchestrator + critic + Ollama client) | Implemented, mock-first test suite. |
| Red-team suite (25 vectors from threat model §16) | Implemented in [`tests/red_team.rs`](tests/red_team.rs). |
| `python-build-standalone` self-contained release | Scaffolded, not yet a one-shot installer. |
| Tauri GUI | Not in v0.1. Planned for v0.2. |
| `grant_scope` / read allowlist / session quotas | Planned for v0.2. |
| `execute_code` (WASI / RustPython) | Planned for v0.3. |

See [`KNOWN_ISSUES.md`](KNOWN_ISSUES.md) for platform-specific caveats.

---

## Install (from source)

Requirements:

- Rust **1.85.0** (pinned in [`rust-toolchain.toml`](rust-toolchain.toml))
- Python **3.12** with [`uv`](https://github.com/astral-sh/uv)
- An [Ollama](https://ollama.com/) install listening on `localhost:11434`
  (for actual LLM use; tests run without it)

```bash
git clone https://github.com/<org>/reliagent
cd reliagent

# Rust side
cargo build --release

# Python sidecar
cd python-core
uv sync
uv pip install -e .
cd ..

# Smoke tests
cargo test
cd python-core && uv run pytest && cd ..
```

The release binary lands at `target/release/reli`.

---

## First run

```bash
# Inspect where things will go (does not create anything yet).
./target/release/reli sandbox path

# See the audit state.
./target/release/reli sandbox status

# Ask the agent to write a file.
./target/release/reli run "create a file called notes.txt with a to-do list"
```

You will be prompted before any side effect. Answering `n`, letting the
prompt time out (60 s), or running with `--non-interactive` all reject
the proposal.

To start over:

```bash
# Wipes the sandbox, audit DB, anchors, and keyring entry. Irreversible.
./target/release/reli reset --wipe-everything
```

### Verifying the log

```bash
./target/release/reli verify
```

`verify` walks the HMAC chain and cross-checks against the anchor log. A
successful verification prints the number of entries and the most recent
HMAC. A failure prints the sequence number where tampering was detected
and drops `reli` into read-only mode until you investigate or reset.

---

## CLI at a glance

| Command | What it does | Exit codes |
|---|---|---|
| `reli run "<prompt>"` | Sends `<prompt>` to the Python sidecar, runs the agent/critic loop, gates every proposed tool call on the policy engine + TTY. | `0` ok, `1` rejected, `2` bad input, `3` audit, `4` bridge, `5` timeout |
| `reli verify` | Re-runs the HMAC chain + anchor cross-check over the whole audit DB. | `0` clean, `3` corrupted |
| `reli sandbox path` | Prints the sandbox root. | `0` |
| `reli sandbox status` | Prints sandbox path, audit entry count, last HMAC, keyring label. | `0` |
| `reli reset --wipe-everything` | Wipes sandbox, audit DB, anchors, and keyring entry. Asks for `WIPE` confirmation unless `--force`. | `0` / `1` |
| `reli ping` | Pings the Python sidecar to confirm the bridge is alive. | `0` / `4` |

Global flag `--non-interactive` turns every approval prompt into an
auto-reject. Use it in CI and scripts.

---

## Layout

```
reliagent/
├── src/                    # Rust crate
│   ├── main.rs
│   ├── cli.rs
│   ├── approval.rs         # TTY gate + 60s timeout
│   ├── bridge/             # JSON-RPC over stdin/stdout to Python
│   └── kernel/
│       ├── policy.rs       # validate_write_path, size caps
│       ├── sandbox.rs      # cap-std capability root
│       ├── tools.rs        # write_file / read_file / list_dir
│       ├── audit.rs        # AuditEntry, HMAC chain
│       ├── store.rs        # SQLite persistence + anchor
│       ├── anchor.rs       # rotating JSONL witness log
│       └── keyring.rs      # OS keyring binding
├── python-core/            # Python sidecar (uv + hatchling)
│   └── src/reliagent_python/
│       ├── orchestrator.py
│       ├── critic.py
│       ├── llm_client.py   # Ollama HTTP client
│       └── __main__.py     # stdin/stdout NDJSON server
├── tests/
│   ├── bridge_jsonrpc.rs   # cross-process bridge integration
│   └── red_team.rs         # 25 adversarial vectors from §16
├── docs/
│   ├── THREAT_MODEL.md
│   └── HASH_FORMAT.md
├── scripts/                # PBS + model fetch scaffolding
└── .github/workflows/      # release signing (cosign + SBOM)
```

---

## Documentation

| File | When to read it |
|---|---|
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Before trusting any security claim. |
| [`docs/HASH_FORMAT.md`](docs/HASH_FORMAT.md) | If you want to write an independent log verifier. |
| [`KNOWN_ISSUES.md`](KNOWN_ISSUES.md) | Before filing a bug. |
| [`SECURITY.md`](SECURITY.md) | Before reporting a vulnerability. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Before opening a PR. |
| [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) | Before interacting with the community. |

---

## Contributing

Short version: bug reports and red-team vectors are the best possible
contribution right now. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

Adversarial paths, canonicalisation edge cases, weird filesystems,
platform-specific surprises — those are exactly what Research Preview is
for.

---

## Licence

[Apache License 2.0](LICENSE). See the `LICENSE` file for the full text.

Third-party model licences are separate:

- Qwen2.5 weights — [Qwen Research Licence](https://huggingface.co/Qwen/Qwen2.5-7B-Instruct).
- Ollama — [MIT](https://github.com/ollama/ollama/blob/main/LICENSE).

You must accept each third-party licence independently of ReliAgent.
