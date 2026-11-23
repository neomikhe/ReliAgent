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

- The model *proposes* a tool call. A deterministic critic and the LLM
  critic can reject it; neither can approve what the kernel refuses.
- The kernel writes the proposal to an HMAC-chained audit log as
  `pending` **before** checking or running it. If that write fails,
  nothing runs.
- A deterministic Rust policy engine validates it (path jail, size cap).
  If the engine says no, the engine wins — the human is not even asked.
- A TTY prompt asks the human. Timeout or no TTY → default reject.
- On approval, the action runs inside a `cap-std` sandbox capability.
- The outcome (`ok`, `rejected` with the reason, or `error`) is written
  as a second entry linked to the `pending` one. The log is signed with a
  key stored in the OS keyring; tampering is detectable with
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
2. **Log before act, tamper-evidence by default.** Every action that
   reaches the kernel — approved, rejected by you or by policy, or failed
   — is HMAC-chained, and it is logged before it can run. A passive
   attacker with disk access can read the log but can't forge entries
   without the keyring key, and can't shorten it unnoticed: the last
   entry is also witnessed in the OS keyring.
3. **No network.** The binary makes zero outbound calls. The Python
   sidecar only talks to `127.0.0.1:11434` (Ollama) — hard-coded, with
   proxies and redirects ignored. You download the model yourself with
   `ollama pull`, and every `reli run` checks its SHA-256 against
   [`MODEL_SHA256.txt`](MODEL_SHA256.txt) before any inference.

If those tradeoffs match how you want local agents to behave, this is for
you. If you need cloud-scale orchestration or production SLAs, this is
not that.

---

## Status: Research Preview (v0.1.0)

| Area | Status |
|---|---|
| Rust kernel (policy engine, sandbox, HMAC chain) | Implemented, ~150 unit tests + property tests. |
| CLI (`reli run / verify / log / sandbox / reset`) | Implemented. |
| Python sidecar (orchestrator + critic + Ollama client) | Implemented. Stdlib-only, no runtime dependencies. Tested against a local fake Ollama server; verified manually against Ollama 0.31.2. |
| Model pinning (`qwen2.5:7b-instruct-q4_K_M`) | Weights SHA-256 pinned and re-checked on every `reli run`. |
| Red-team suite (26 vectors) | [`tests/red_team.rs`](tests/red_team.rs): 22 run (some only on the platform they target); 4 are pinned as ignored until the feature they test exists — session quota and `grant_scope` (v0.2), byte-exact JCS (next hash format). |
| Self-contained release (binary + pinned python-build-standalone runtime + sidecar) | Implemented: `scripts/package_release.sh`, built and smoke-tested per platform by the release workflow. |
| Tauri GUI | Not in v0.1. Planned for v0.2. |
| `grant_scope` / read allowlist / session quotas | Planned for v0.2. |
| `execute_code` (WASI / RustPython) | Planned for v0.3. |

See [`KNOWN_ISSUES.md`](KNOWN_ISSUES.md) for platform-specific caveats.

---

## Install

Both ways need an [Ollama](https://ollama.com/) install listening on
`127.0.0.1:11434` with the canonical model pulled, for actual LLM use
(tests and `--mock-llm` run without it):

```bash
ollama pull qwen2.5:7b-instruct-q4_K_M   # ~4.7 GB
```

### From a release

Each release archive is self-contained: the `reli` binary, a pinned
[python-build-standalone](https://github.com/astral-sh/python-build-standalone)
runtime in `python/` (SHA-256 in [`scripts/pbs.lock`](scripts/pbs.lock))
with the sidecar installed, and the docs. No system Python is needed.

```bash
# Verify the archive first; the release notes give the exact identity.
cosign verify-blob --certificate <archive>.cert --signature <archive>.sig \
    --certificate-identity "https://github.com/<owner>/<repo>/.github/workflows/release.yml@refs/tags/v0.1.0" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com <archive>
gh attestation verify <archive> --repo <owner>/<repo>

tar -xzf reli-v0.1.0-linux-x86_64.tar.gz      # or unzip the Windows .zip
cd reli-v0.1.0-linux-x86_64
./reli ping                                    # finds ./python by itself
```

Keep `python/` next to `reli` (that is where `reli` looks for it), and
extract as the user who will run it into a directory only that user can
write: `reli` trusts that folder (see [KNOWN_ISSUES.md](KNOWN_ISSUES.md)).
On Linux, `reli` needs `libdbus-1.so.3` and a running Secret Service
(gnome-keyring, KeePassXC, KWallet) for the OS keyring; desktop
distributions have both, minimal containers may not.

### From source

Requirements: Rust **1.85.0** (pinned in
[`rust-toolchain.toml`](rust-toolchain.toml)) and Python **3.12** with
[`uv`](https://github.com/astral-sh/uv). On Linux, also the D-Bus headers
and `pkg-config` (`sudo apt-get install libdbus-1-dev pkg-config` on
Debian/Ubuntu, `dbus-devel pkgconf` on Fedora).

```bash
git clone https://github.com/<org>/reliagent
cd reliagent

# Rust side
cargo build --release

# Python sidecar: `uv sync` creates python-core/.venv with the package installed
(cd python-core && uv sync --extra dev)

# Tell reli which interpreter runs the sidecar
export RELI_PYTHON="$PWD/python-core/.venv/bin/python"      # Windows: python-core\.venv\Scripts\python.exe

# Smoke tests
cargo test
(cd python-core && uv run pytest)
./target/release/reli ping
```

`reli` looks for the sidecar interpreter in this order: `--python <path>`,
`$RELI_PYTHON`, `python/` next to the `reli` executable (release layout),
then `python3` (`python` on Windows) from `PATH`. It starts it in isolated
mode (`python -I`), so that interpreter must have `reliagent_python`
installed. To build a release-style directory locally, see
[`scripts/README.md`](scripts/README.md).

---

## First run

The examples use a source build (`./target/release/reli`, with
`RELI_PYTHON` set as above); from a release, run `./reli` inside the
extracted folder instead.

```bash
# Inspect where things will go (does not create anything yet).
./target/release/reli sandbox path

# See the audit state.
./target/release/reli sandbox status

# Ask the agent to write a file.
./target/release/reli run "create a file called notes.txt with a to-do list"
```

Before the first inference, `reli run` checks that Ollama is reachable,
that it has the pinned model, and that the model file on disk matches the
SHA-256 in [`MODEL_SHA256.txt`](MODEL_SHA256.txt). If any check fails it
stops and tells you what to do (start Ollama, `ollama pull ...`, or
re-download a model that does not match).

You will be prompted before any side effect. Answering `n`, letting the
prompt time out (60 s), or running with `--non-interactive` all reject
the proposal.

No Ollama at hand? `reli run --mock-llm "write 'hola' to notes/hi.txt"`
uses a deterministic test agent that understands only simple phrasings.
Everything after the agent (policy engine, approval, audit log) is the
same.

To start over:

```bash
# Wipes the sandbox, audit DB, anchors and the keyring entries (HMAC key
# and head witness). Irreversible. Use this instead of deleting
# ~/.reliagent by hand, which would look like tampering.
./target/release/reli reset --wipe-everything
```

### Verifying the log

```bash
./target/release/reli verify
```

`verify` walks the HMAC chain and cross-checks it against the anchor log
and the head witness kept in the OS keyring. A successful verification
prints the number of entries, the most recent HMAC and any action still
waiting for its outcome. A failure prints the sequence number where tampering was detected,
and from then on `reli` stays in **read-only mode** until you investigate
or reset: every command that would act refuses to run (exit code `3`),
and nothing is repaired for you.

```bash
./target/release/reli log > audit-export.jsonl
```

`log` prints every entry exactly as it is stored, one JSON object per
line, and then reports on stderr whether the log verifies (exit `0`) or
where it breaks (exit `3`). It works on a healthy log too, and it never
modifies the log: it reads through a read-only SQLite connection, never
migrates, and creates no key, anchor or witness. Control and invisible
characters are written as JSON escapes, so the export is safe to `cat`
or `grep` in a terminal. If the database holds anything `reli` never
creates (a view, a trigger, an extra column) it refuses to export and
asks you to analyse a copy. The byte-level format is in
[`docs/HASH_FORMAT.md`](docs/HASH_FORMAT.md).

Each action appears as two entries: `pending` (written before the policy
check, approval and execution) and its outcome. If `reli` is killed
between the two, the next run records the leftover `pending` as
`abandoned` — "may or may not have run" — and names it on the terminal.
Only one `reli` process can use the log at a time; a second one waits
about 2 s and exits with code `6` (busy, not tampering).

---

## CLI at a glance

| Command | What it does | Exit codes |
|---|---|---|
| `reli run "<prompt>"` | Sends `<prompt>` to the Python sidecar, verifies Ollama and the pinned model, runs the agent/critic loop, gates every proposed tool call on the policy engine + TTY. `--dry-run` only shows the proposal; `--mock-llm` uses the deterministic test agent instead of Ollama. | `0` ok, `1` rejected, `2` bad input, `3` audit, `4` bridge / Ollama / model check, `5` timeout, `6` log in use |
| `reli verify` | Re-runs the HMAC chain, anchor and head-witness checks over the whole audit DB. | `0` clean, `3` corrupted, `6` log in use |
| `reli log` | Read-only: prints every audit entry as JSON Lines (invisible and control characters escaped), then the verification result. Also works on a log that fails verification. | `0` clean, `3` corrupted or not verifiable, `6` log in use |
| `reli sandbox path` | Prints the sandbox root. | `0` |
| `reli sandbox status` | Prints sandbox path, audit entry count, last HMAC, keyring label, open actions. | `0` / `6` |
| `reli reset --wipe-everything` | Wipes sandbox, audit DB (and its migration backup), anchors, and the keyring entries. Asks for `WIPE` confirmation unless `--force`; refuses while another `reli` uses the log. | `0` / `1` / `6` |
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
│       ├── llm_client.py   # client protocol + deterministic mock
│       ├── ollama_http.py  # stdlib HTTP client, loopback-only
│       ├── model_integrity.py  # pinned model SHA-256 check
│       └── __main__.py     # stdin/stdout NDJSON server
├── tests/
│   ├── bridge_jsonrpc.rs   # cross-process bridge integration
│   └── red_team.rs         # 26 adversarial vectors
├── docs/
│   ├── THREAT_MODEL.md
│   └── HASH_FORMAT.md
├── scripts/                # release packaging (pinned Python runtime)
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

Third-party components you install separately have their own licences:

- Qwen2.5-7B-Instruct weights — [Apache 2.0](https://huggingface.co/Qwen/Qwen2.5-7B-Instruct/blob/main/LICENSE)
  (other Qwen2.5 sizes use different licences).
- Ollama — [MIT](https://github.com/ollama/ollama/blob/main/LICENSE).

You accept each of them independently of ReliAgent.
