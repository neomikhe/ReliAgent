# Changelog

All notable changes to ReliAgent. Dates are in UTC. The audit log format
has its own version history in [`docs/HASH_FORMAT.md`](docs/HASH_FORMAT.md)
(§8).

## v0.1.0 — Research Preview (unreleased)

First public release. A local kernel for AI agents: every action a local
model proposes is logged before it runs, checked by a deterministic Rust
policy engine and needs your approval on the terminal before it touches
the file system; its outcome is recorded in a tamper-evident audit log.

### Kernel and CLI (`reli`)
- Sandbox on `cap-std` with explicit path rules: no traversal, absolute or
  drive paths, Windows device prefixes, alternate data streams, null
  bytes, or control and invisible characters (bidi, zero-width, tag
  characters, …) in any path.
- Tools: `write_file` (≤ 10 MiB), `read_file`, `list_dir`, all inside the
  sandbox. Reading outside it is always refused.
- Audit log (hash format v2): every action is logged as `pending` before
  the policy check, approval and execution, then resolved as `ok`,
  `error` or `rejected`. HMAC-SHA256 chain with the key in the OS
  keyring, an anchor log and a head witness in the keyring that catches
  truncation or deletion of the whole log. One process at a time
  (exit code `6` when the log is in use).
- Strict schema allow-list for `audit.db` (only reli's tables, indexes
  and columns) and hardened SQLite settings.
- Read-only mode when verification fails: every command that would act
  refuses (exit code `3`); `reli log` exports the entries as JSON Lines
  and reports where the log breaks, without modifying anything.
- `reli run` asks the local agent for a proposal, runs it through the
  deterministic critic and an LLM critic (which can only reject), shows
  it, and asks for approval on the terminal (60 s timeout;
  `--non-interactive` rejects). `--dry-run` and `--mock-llm` for demos.
- Direct commands `reli write`, `read` and `ls` (policy-checked and
  logged, not prompted), `verify`, `log`, `sandbox path|status`,
  `reset --wipe-everything` and `ping`. Messages, `--help` and the
  approval prompt are in English (`y`/`yes` approves; `s`/`si` are
  accepted too).
- On a terminal, `reli read` escapes control characters and ends the last
  line, so its status message never runs into the file's content;
  redirected, it writes the exact bytes.
- Logs written by earlier development builds (format v1) are migrated
  one way to v2 on first open, with a backup (`audit.db.schema1.bak`).
- Red-team suite of 27 vectors (`tests/red_team.rs`); 4 are pinned as
  ignored until the features they test exist.

### Python sidecar
- Orchestrator, critics and an Ollama client using only the Python
  standard library, spoken to over JSON-RPC 2.0 (NDJSON) on stdin/stdout,
  started in isolated mode (`python -I`).
- Talks only to `127.0.0.1:11434`: `OLLAMA_HOST`, proxy variables and
  redirects are ignored.
- The pinned model (`qwen2.5:7b-instruct-q4_K_M`) is verified against its
  SHA-256 in [`MODEL_SHA256.txt`](MODEL_SHA256.txt) before every run.
- Warns when the running Ollama version has not been audited
  ([`audits/`](audits/)).

### Release
- Self-contained archives for Linux x86-64, macOS arm64 and Windows
  x86-64: the binary, a pinned python-build-standalone runtime (SHA-256 in
  [`scripts/pbs.lock`](scripts/pbs.lock)) and the sidecar. No system
  Python needed.
- Built by a read-only job; signed with cosign (keyless) by a separate
  job, with build provenance attestations and SPDX/CycloneDX SBOMs.
- On Linux and macOS `reli` refuses a bundled runtime that other users
  can modify.

### Security
- Dependencies checked against the OSV / RustSec advisory databases
  before release; none open. Fixed on the way:
  - `cap-primitives` 4.0.3 (RUSTSEC-2026-0482): a symlink whose target
    ends in a path separator could lead a directory listing out of the
    sandbox through cap-std's portable resolver (used on Windows and
    macOS). ReliAgent's own tools were not exploitable thanks to their
    metadata check, but the dependency is fixed and red-team vector 27
    pins it.
  - Bundled SQLite 3.54.1 via `rusqlite` 0.41 (CVE-2026-119375,
    RUSTSEC-2026-0459: uninitialised memory with a crafted `-wal` file).
  - `rustix` 1.1.6, `anyhow` 1.0.104 and `time` 0.3.55, for advisories in
    functions ReliAgent does not call.
- Rust toolchain 1.99.1 (needed by the fixed SQLite).
- A newly created HMAC key is read back from the keyring before use.

### Known limitations
See [`KNOWN_ISSUES.md`](KNOWN_ISSUES.md) and
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) §4.
