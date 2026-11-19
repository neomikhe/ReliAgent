# Threat Model — ReliAgent v0.1.0 (Research Preview)

> **Status:** Research Preview. This document describes what v0.1.0 actually
> defends against today, not what future versions aim to achieve. Anything
> outside the "In scope" section is **explicitly out of scope**.

## Purpose

ReliAgent is a local trusted kernel for AI agents: a policy engine and a
tamper-evident audit log that sit between an LLM orchestrator and the
user's filesystem. This document enumerates the actors, assets, attack
vectors and mitigations we considered while building v0.1.0, and is linked
from every user-facing doc that makes a security claim.

If ReliAgent's behaviour ever contradicts this document, the contradiction
is a bug. Open an issue against this file in the same PR.

---

## 1. Actors

| # | Actor | Capability assumed | Treated as |
|---|---|---|---|
| 1 | **Legitimate user** | Runs the binary, approves or rejects proposals, reads the log. | Trusted. |
| 2 | **LLM / orchestrator** | Generates proposals (tool + args). May be adversarial, hallucinating, or a victim of prompt injection via file content. | **Untrusted.** Every proposal passes the Rust policy engine before any side effect. |
| 3 | **Offline file-system attacker** | Can read and modify files on disk (the SQLite DB, the sandbox, `anchor.log`) but does **not** have code execution as the user and cannot read the OS keyring. | Partially mitigated (see §4). |
| 4 | **Process running as the user** | Can read the keyring, `ptrace`, dump memory, replace the binary on disk. | **Out of scope.** If an attacker already executes code as the user, the kernel cannot defend against them. |
| 5 | **Compromised dependency** | A malicious crate, a malicious Ollama build, a model file swapped after download. | Partially mitigated (pinned versions, SHA256 model pinning, SBOM at release). Residual risk documented. |
| 6 | **Physical attacker** | Cold-boot, DMA, evil-maid, TPM attacks. | **Out of scope.** |

---

## 2. Assets

| # | Asset | Protection |
|---|---|---|
| A | Files **outside** the sandbox root (`~/ReliAgent_Sandbox/`). | Writes forbidden by default; path validation + `cap-std` capability. Reads follow the same rule (v0.2 will add an opt-in read allowlist with per-file approval). |
| B | Integrity of the action log. | Linear HMAC-SHA256 chain over every recorded entry; `anchor.log` as external witness against truncation. |
| C | HMAC key. | Stored in the OS keyring (Windows Credential Manager, macOS Keychain, libsecret on Linux). Never written to disk in plaintext, never logged. |
| D | Approval gate. | TTY prompt before any mutating proposal executes. In non-interactive mode or without a TTY, the default is **reject**. |
| E | Privacy of the user. | Zero outbound network traffic from `reli` itself. The Python sidecar talks to Ollama on `127.0.0.1:11434` only: the host is hard-coded, and `OLLAMA_HOST`, proxy environment variables and HTTP redirects are ignored. Model downloads happen only when the user runs `ollama pull`. |

---

## 3. Vectors and mitigations

All vectors below are exercised by `tests/red_team.rs`. Mitigations live in
deterministic Rust code — the LLM critic is a second layer only and
**cannot** approve anything the engine rejected.

### 3.1 Path-based attacks

| Vector | Mitigation |
|---|---|
| `..` traversal (`../../etc/passwd`) | `validate_write_path` rejects any `ParentDir` component before I/O. |
| Unicode homoglyph pseudo-traversal (`．．/…`) | Fullwidth dots are not parsed as `ParentDir`; the segment becomes a literal directory name inside the sandbox. Escape cannot succeed. |
| Absolute path (`/etc/…`, `C:\…`) | Rejected as `PathOutsideSandbox`. Windows drive-relative forms (`C:foo`) are rejected before normalization. |
| Windows extended-length prefix `\\?\` or device prefix `\\.\` | Rejected as `InvalidPath`. |
| NTFS alternate data streams (`file.txt:hidden`) | Any `:` in the filename segment on Windows is rejected. |
| Null byte injection (`foo.txt\0.jpg`) | Rejected as `InvalidPath`. |
| Empty components collapsing to `..` (`foo//../bar`) | `Path::components` still emits `ParentDir`; rejected. |
| Symlink-swap TOCTOU | `cap-std` opens every file through the sandbox capability; it does not follow symlinks that escape the root. |

### 3.2 Content-based attacks

| Vector | Mitigation |
|---|---|
| Oversized write (> 10 MiB) | `write_file` checks size **before** opening any file handle; returns `FileTooLarge`. |
| Prompt injection via file content (`IGNORE PREVIOUS INSTRUCTIONS…`) | `read_file` / `list_dir` return bytes. The kernel never interprets file content as instructions. Interpretation (if any) happens in the Python orchestrator, which has no ability to bypass the kernel's policy. |
| CRLF / control characters in tool arguments | JSON serialisation escapes them; they become opaque string bytes inside the `args_hash`. One action in, exactly one `pending` + one resolution entry out. |
| Deeply nested JSON as tool args (DoS) | `serde_json` has a default recursion limit; reasonable depths record and verify without panic. |

### 3.3 Audit log attacks

| Vector | Mitigation |
|---|---|
| HMAC byte flip in the DB | Every entry recomputes HMAC-SHA256 on `open`. Byte-flip tests exhaust all 32 bytes of every test entry. |
| `prev_hmac` tampering (broken chain link) | `verify()` walks the chain; mismatch aborts open with `AuditCorrupted`. |
| Intermediate row deletion | `sequence_no` contiguity check catches the gap. |
| Tail truncation (delete the last rows) | In-DB chain alone cannot detect this. `anchor.log` (outside the DB, same disk, unkeyed) catches a truncation of the DB alone. A **head witness** in the OS keyring (last `sequence_no` + HMAC, one entry per log) catches a coordinated truncation of DB *and* anchor, and a deleted or replaced `audit.db`: a log shorter than its witness fails with `AuditCorrupted`. |
| Planted trigger or view in `audit.db` (e.g. `RAISE(IGNORE)` turning every INSERT into a silent no-op) | `reli` refuses to open a database that contains any trigger or view, and every INSERT must report exactly one written row. |
| Editing columns that look meaningful but are not signed | `status_reason` must be NULL for `pending`/`ok` and non-NULL for `error`/`rejected`; anything else is `AuditCorrupted`. |
| Forcing the destructive v1→v2 migration on a v2 log (setting `schema_version` back to `1`) | Refused when the table already has v2 columns; a real v1 log is backed up (`audit.db.schema1.bak`) before migrating. |
| Replay: insert a duplicate `sequence_no` | SQLite `UNIQUE` / `PRIMARY KEY` constraint rejects it at INSERT time; even if injected via raw SQL, the chain re-verification fails. |
| Clock rollback or past-timestamp forgery | Timestamp is inside the HMAC input; any change breaks the chain. Ordering is enforced by `sequence_no`, not the clock. |
| Wrong HMAC key on reopen (including deleted keyring entry) | Re-verification fails with `AuditCorrupted`. |
| Side effect with no log entry (crash, power loss or log failure between acting and logging) | **Log before act:** a `pending` entry is committed with `synchronous = FULL` (plus `fullfsync` on macOS), and its anchor line and head witness are written, before approval and execution; if any of that fails, nothing runs. A `pending` left without outcome is closed as `error`/`abandoned` ("may or may not have run") by the next session, which names it on the terminal. |
| Two `reli` processes racing on the log (or one closing the other's in-flight `pending` as abandoned) | The database is opened with an exclusive file lock; a second process (including `reli reset`) waits about 2 s and exits with code `6`. |
| Forged or inconsistent outcome (resolving a non-pending row, resolving twice, outcome for different args) | Checked by `verify()` for every v2 row, plus a `UNIQUE` index on `resolves_seq`. Only possible at all with the HMAC key. |

### 3.4 Orchestration / approval attacks

| Vector | Mitigation |
|---|---|
| Non-interactive run silently auto-approving | Default in non-TTY / `--non-interactive` mode is **reject**, recorded as `rejected` / `non_interactive`. |
| Stalled operator blocking a batch | 60-second timeout; on expiry the proposal is rejected (`timeout`), not approved. |
| Rejected proposals leaving no trace | Every proposal that reaches the kernel is logged as `pending` before the prompt; refusals are logged as `user_denied`, `timeout` or `non_interactive`. Proposals the critic rejects, malformed proposals and `--dry-run` never reach the kernel and are not logged. |
| A human approving (or hiding) a rule-violating proposal | Path and size rules run **before** the prompt; a violation is logged as `rejected` / `policy: …` and the human is not asked. |
| Using the log as a data channel (an LLM-chosen path stored in clear) | Arguments are only stored as `args_hash`; refusal reasons are fixed codes (`policy: path_outside_sandbox`, `io: NotFound`, …), never the path or OS error text. |
| Orchestrator forging a proposal as "already approved" | The Rust kernel owns the approval gate; the Python side can only *propose*. |
| LLM critic "approving" a rule-violating action | The critic is architecturally downstream of the policy engine and can only reject further. A critic approval never overrides a hard-rule rejection. |

---

## 4. Residual risk

These are things ReliAgent v0.1.0 does **not** fully defend against.
They are documented here so no user is surprised.

- **Code execution as the user.** If an attacker runs arbitrary code as the
  user account, they can read the keyring, decrypt or forge log entries,
  replace the binary on disk, or intercept TTY approvals. This is the
  classic threat-model boundary of a user-space trusted kernel.
- **Supply-chain compromise.** A malicious Rust crate, Python wheel, or
  Ollama binary can undermine everything above. Mitigations: pinned
  versions, `cargo --locked` in CI, SBOM + `cosign` signature on releases
  (tracked in §6 and the release workflow).
- **Model substitution.** Every `reli run` refuses to infer unless the
  server on `127.0.0.1:11434` reports a Modelfile with a single `FROM`
  (no `ADAPTER`) pointing to the blob pinned in `MODEL_SHA256.txt`, that
  path is a local absolute path inside a `blobs/` directory (never UNC or
  device paths), and the file's SHA-256 still matches. Not covered:
  Ollama's template/system/parameter layers for the tag; a model already
  resident in Ollama's memory from before a swap; re-tagging between the
  check and the inference (needs write access to Ollama's model store).
- **Port squatting.** The check above verifies a *file*, not the process
  answering on `127.0.0.1:11434`. If Ollama is not running, **any local
  account** — not only code running as the user — can bind that port,
  point the check at the genuine blob, and then receive every prompt and
  dictate the agent's and the critic's answers. What it cannot do is
  bypass the Rust policy engine or the TTY approval: its proposals go
  through the same gates as Ollama's. On shared machines, keep Ollama
  running (or bound) before using `reli run`.
- **The LLM critic is not independent.** It is the same model and client
  as the agent, so a prompt injection that steers the agent can steer the
  critic too. It is defence in depth on top of the deterministic critic
  and the Rust policy engine, never a replacement.
- **Side channels on the keyring.** Memory scraping, debugger attach,
  weaknesses in the OS keyring implementation itself.
- **Linux without libsecret.** Fallback to a local encrypted file is a
  strict downgrade versus a native keyring. Documented in
  `KNOWN_ISSUES.md`.
- **Sandbox contents are not covered by the log.** The log records which
  actions ran (tool, `args_hash`, outcome), not what the files contain.
  An antivirus — or anyone — that rewrites or quarantines a sandboxed file
  afterwards is **not** detected by `reli verify`.
- **Rollback of the OS credential store.** The head witness relies on the
  keyring being out of reach of an attacker who can only modify files. On
  Windows the Credential Manager is itself stored in (DPAPI-encrypted)
  files: someone who saved an old copy of them can restore it together
  with an older, consistent copy of `audit.db` and `anchors/`. Only an
  external or hardware-backed witness (TPM, remote log) would stop that.
- **Network file systems.** SQLite's file locks are unreliable on SMB/NFS.
  Keep `~/.reliagent/` on a local disk; on a network share two `reli`
  processes could race despite the exclusive lock.
- **SHA-256 collision resistance.** Treated as cryptographically sound in
  2026; a break in SHA-256 would invalidate the chain.

---

## 5. Out of scope (by policy)

- Root / administrator privilege escalation.
- Physical attacks (cold-boot, DMA, evil-maid, TPM bypass if no TPM is
  configured).
- Malicious behaviour inside the user's own legitimate process tree.
- Non-audited Ollama or model versions. Each release pins an Ollama
  version it was tested against; newer versions ship at the user's risk
  until re-audited.
- Bugs in CPython, Rust stdlib, or `rusqlite` / `cap-std` / `hmac` /
  `sha2`. These are treated as trusted computing base.

---

## 6. Change control

- This file is part of the repository and versioned alongside the code.
- Any PR that weakens a guarantee here must update this file in the same
  commit, with rationale.
- New rows are written with `hash_format_version = 2`; version `1` rows
  remain verifiable. Any change to the fields covered by HMAC or the
  serialisation order requires bumping it and writing a migration. See
  [`HASH_FORMAT.md`](HASH_FORMAT.md).

---

## 7. Related documents

- [`HASH_FORMAT.md`](HASH_FORMAT.md) — byte-level spec of the audit entry
  and its HMAC.
- [`../SECURITY.md`](../SECURITY.md) — how to report a vulnerability.
- [`../KNOWN_ISSUES.md`](../KNOWN_ISSUES.md) — platform-specific caveats.
- `tests/red_team.rs` — the executable version of §3.
