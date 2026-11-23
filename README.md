# ReliAgent

> A local kernel between AI agents and your files. Before any action a
> local model proposes touches the file system, it is logged in a
> tamper-evident, HMAC-chained audit log, checked by a deterministic
> policy engine in Rust, and approved by you. ReliAgent itself makes no
> network connections; the model runs in a local Ollama.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
![status](https://img.shields.io/badge/status-research%20preview-orange)
![platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey)

---

## What this is

ReliAgent is a **CLI-first research preview** of a different way to run
local AI agents. Instead of trusting the LLM with direct filesystem access
(as many agent setups do, by handing the model a shell or file-system
tool), ReliAgent puts a small Rust kernel between the model and the OS:

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
  as a second entry linked to the `pending` one. Each entry carries an
  HMAC-SHA256 under a key kept in the OS keyring; tampering is detectable
  with `reli verify`.

```
prompt → sidecar: model proposes → deterministic critic → LLM critic (can only reject)
       → kernel:  log `pending` → policy engine → your y/N → cap-std sandbox → log outcome
```

You trust `reli`, its bundled `python/` folder, your OS account and its
keyring. The log does **not** cover what files contain now (an antivirus
or you can change them later), proposals the critics already rejected
(they never reach the kernel), or anything after someone ran code as you.

**What this is not.** It is not blockchain, not "provably secure", not a
production-ready agent framework. It is a Research Preview focused on one
question: *can we make local agents auditable and human-gated by default,
with no cloud and no magic?*

For the threat model and what is explicitly **out of scope**, read
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) before relying on anything
here.

---

## Why

Many local-agent setups share a bad habit: when the LLM hallucinates
`rm -rf /`, the shell runs it. When it's prompt-injected by a file it just
read, nothing in the stack notices. ReliAgent's answer:

1. **Determinism has the last word.** The model and the critics can only
   propose or veto; the hard rules in Rust (path jail, size cap) and your
   y/N decide after every LLM step, and no LLM can override them.
2. **Log before act, tamper-evidence by default.** Every action that
   reaches the kernel — approved, rejected by you or by policy, or failed
   — is HMAC-chained, and it is logged before it can run. Someone who can
   read and change your files, but cannot run code as you, can read the
   log but cannot forge entries without the keyring key, nor shorten it
   unnoticed: the last entry is also witnessed in the OS keyring (on
   Windows, restoring an old copy of the whole credential store together
   with the log defeats this; see THREAT_MODEL §4).
3. **No network from ReliAgent.** The binary makes zero outbound calls. The Python
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
| Rust kernel (policy engine, sandbox, HMAC chain) | Implemented, 200+ unit tests + property tests. |
| CLI (`reli run / write / read / ls / verify / log / sandbox / reset / ping`) | Implemented. Messages, `--help` and the approval prompt are in Spanish in v0.1.0. |
| Python sidecar (orchestrator + critic + Ollama client) | Implemented. Stdlib-only, no runtime dependencies. Tested against a local fake Ollama server and against Ollama 0.31.2, whose network behaviour is audited in [`audits/`](audits/) (run it with `OLLAMA_NO_CLOUD=1`). |
| Model pinning (`qwen2.5:7b-instruct-q4_K_M`) | Weights SHA-256 pinned and re-checked on every `reli run`. |
| Red-team suite (26 vectors) | [`tests/red_team.rs`](tests/red_team.rs): 22 run (some only on the platform they target); 4 are pinned as ignored until the feature they test exists — session quota and `grant_scope` (v0.2), byte-exact JCS (next hash format). |
| Self-contained release (binary + pinned python-build-standalone runtime + sidecar) | Implemented: `scripts/package_release.sh`, built and smoke-tested per platform by the release workflow. |
| Tauri GUI | Not in v0.1. Planned for v0.2 or later. |
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

Then run Ollama with `OLLAMA_NO_CLOUD=1`. Without it, Ollama contacts
`ollama.com` on its own at start-up and every few hours (model
recommendations, cloud catalogue); ReliAgent needs none of that. Details
in [`audits/ollama_v0.31.2.md`](audits/ollama_v0.31.2.md).

```bash
OLLAMA_NO_CLOUD=1 ollama serve                 # Linux / macOS
$env:OLLAMA_NO_CLOUD = "1"; ollama serve       # Windows PowerShell
```

For the desktop app, set `OLLAMA_NO_CLOUD=1` as a user environment
variable and restart the app; for the Linux systemd service, run
`sudo systemctl edit ollama` and add `Environment=OLLAMA_NO_CLOUD=1`
under `[Service]`.

### From a release

Each release archive is self-contained: the `reli` binary, a pinned
[python-build-standalone](https://github.com/astral-sh/python-build-standalone)
runtime in `python/` (SHA-256 in [`scripts/pbs.lock`](scripts/pbs.lock))
with the sidecar installed, and the docs. No system Python is needed.

1. From <https://github.com/neomikhe/ReliAgent/releases>, download your
   platform's archive **and** its `.cert` and `.sig` files:
   `reli-v0.1.0-linux-x86_64.tar.gz`, `reli-v0.1.0-macos-aarch64.tar.gz`
   (Apple Silicon) or `reli-v0.1.0-windows-x86_64.zip`. There is no Intel
   Mac or ARM Linux build in v0.1.0: build from source there.
2. Verify it (needs [cosign](https://github.com/sigstore/cosign) and a
   signed-in [`gh`](https://cli.github.com/)), then extract and run:

```bash
A=reli-v0.1.0-linux-x86_64.tar.gz
cosign verify-blob --certificate "$A.cert" --signature "$A.sig" \
    --certificate-identity "https://github.com/neomikhe/ReliAgent/.github/workflows/release.yml@refs/tags/v0.1.0" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com "$A"
gh attestation verify "$A" --repo neomikhe/ReliAgent \
    --signer-workflow neomikhe/ReliAgent/.github/workflows/release.yml

tar -xzf "$A"                                  # or unzip the Windows .zip
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
git clone https://github.com/neomikhe/ReliAgent.git
cd ReliAgent

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

`cargo test` starts real Python processes: it needs `python3` (`python`
on Windows) on `PATH`. If that is missing or is the Microsoft Store alias,
set `RELI_TEST_PYTHON` to the venv interpreter (see
[CONTRIBUTING.md](CONTRIBUTING.md)).

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

`reli run` prompts you before any side effect. Answering `n`, letting
the prompt time out (60 s), or running with `--non-interactive` all
reject the proposal. In v0.1.0 the CLI's messages, `--help` and the
approval prompt (`¿aprobar propuesta? [y/N]`) are in Spanish;
`y`/`yes`/`s`/`si` approve, anything else rejects. The direct commands
`reli write`, `reli read` and `reli ls` are not prompted: typing the
command is your approval (they are still policy-checked and logged).

> **`--sandbox` is the jail.** The agent can read and write anything
> under it, and `reli reset --wipe-everything` deletes everything inside
> it. Never point `--sandbox` at a directory that holds anything else.

No Ollama at hand? `reli run --mock-llm "write 'hola' to notes/hi.txt"`
uses a deterministic test agent that understands only simple phrasings
(the LLM critic is skipped too). Everything after the agent (policy
engine, approval, audit log) is the same.

To start over:

```bash
# Wipes the sandbox, audit DB, anchors and the keyring entries (HMAC key
# and head witness). Irreversible. Use this instead of deleting
# ~/.reliagent by hand, which would look like tampering.
./target/release/reli reset --wipe-everything
```

All audit logs on the machine share one HMAC key, and `reset` deletes
it: if you use several `--audit-dir` values, every *other* log stops
verifying afterwards. Export them with `reli log` first.

### Verifying the log

```bash
./target/release/reli verify
```

`verify` walks the HMAC chain and cross-checks it against the anchor log
and the head witness kept in the OS keyring. A successful verification
prints the number of entries, the most recent HMAC and any action still
waiting for its outcome. A failure prints the sequence number where tampering was detected,
and from then on `reli` stays in **read-only mode**: every command that
would act refuses to run (exit code `3`) until the log verifies again or
you run `reli reset --wipe-everything`, and nothing is repaired for you.

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
| `reli write <path> <content>` / `reli read <path>` / `reli ls [path]` | Direct actions inside the sandbox: logged and policy-checked like an agent proposal, but **not prompted** (typing the command is your approval). | `0` ok, `1` policy, `2` bad input or I/O, `3` audit, `6` log in use |
| `reli verify` | Re-runs the HMAC chain, anchor and head-witness checks over the whole audit DB. | `0` clean, `3` corrupted, `6` log in use |
| `reli log` | Read-only: prints every audit entry as JSON Lines (invisible and control characters escaped), then the verification result. Also works on a log that fails verification. | `0` clean (or no log yet), `2` output could not be written, `3` corrupted or not verifiable, `6` log in use |
| `reli sandbox path` | Prints the sandbox root. | `0` |
| `reli sandbox status` | Prints sandbox path, audit entry count, last HMAC, keyring label, open actions. | `0` / `3` log fails verification or keyring unreadable / `6` |
| `reli reset --wipe-everything` | Wipes sandbox, audit DB (and its migration backup), anchors, and the keyring entries (including the HMAC key shared by every log). Asks for `WIPE` confirmation unless `--force`; refuses while another `reli` uses the log. | `0` / `1` aborted / `2` no `--wipe-everything` / `3` partial failure / `6` |
| `reli ping` | Pings the Python sidecar to confirm the bridge is alive. | `0` / `4` |

Global flags: `--sandbox <dir>` (default `~/ReliAgent_Sandbox`),
`--audit-dir <dir>` (default `~/.reliagent`), `--python <path>`,
`--python-cwd <dir>`, and `--non-interactive`, which turns every approval
prompt into an auto-reject (use it in CI and scripts).

---

## Layout

```
ReliAgent/
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
│       ├── store.rs        # SQLite persistence, schema checks, reli log reader
│       ├── anchor.rs       # rotating JSONL witness log
│       ├── head.rs         # head witness (last entry, kept in the keyring)
│       ├── keyring.rs      # OS keyring binding
│       └── migrations/     # v1.sql, v2.sql
├── python-core/            # Python sidecar (uv + hatchling)
│   └── src/reliagent_python/
│       ├── orchestrator.py
│       ├── critic.py
│       ├── llm_client.py   # client protocol + deterministic mock
│       ├── ollama_http.py  # stdlib HTTP client, loopback-only
│       ├── model_integrity.py  # pinned model SHA-256 check
│       ├── main.py         # JSON-RPC server over stdin/stdout (NDJSON)
│       └── __main__.py     # entry point for `python -I -m reliagent_python`
├── tests/
│   ├── bridge_jsonrpc.rs   # cross-process bridge integration
│   └── red_team.rs         # 26 adversarial vectors
├── docs/
│   ├── THREAT_MODEL.md
│   ├── HASH_FORMAT.md
│   └── RELEASING.md        # maintainer release checklist
├── audits/                 # network audits of each targeted Ollama version
├── scripts/                # release packaging (pinned Python runtime)
└── .github/                # test.yml (CI), release.yml (cosign + SBOM), Dependabot
```

---

## Documentation

| File | When to read it |
|---|---|
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Before trusting any security claim. |
| [`docs/HASH_FORMAT.md`](docs/HASH_FORMAT.md) | If you want to write an independent log verifier. |
| [`audits/`](audits/) | To see what the targeted Ollama version connects to, and how to turn it off. |
| [`CHANGELOG.md`](CHANGELOG.md) | To see what changed in each release. |
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
