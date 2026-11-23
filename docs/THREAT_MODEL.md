# Threat Model — ReliAgent v0.1.0 (Research Preview)

> **Status:** Research Preview. This document describes what v0.1.0 actually
> defends against today, not what future versions aim to achieve. Anything
> not listed in §3 is out of scope; §4 lists what is known not to be fully
> covered, §5 what is excluded by policy.

## Purpose

ReliAgent is a local policy-and-audit kernel for AI agents: a policy engine and a
tamper-evident audit log that sit between an LLM orchestrator and the
user's filesystem. This document enumerates the actors, assets, attack
vectors and mitigations we considered while building v0.1.0.

If ReliAgent's behaviour ever contradicts this document, the contradiction
is a bug. Report it as an issue (privately, via SECURITY.md, if it weakens
a security claim); the PR that fixes it updates this file too.

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
| C | HMAC key. | Stored in the OS keyring (Windows Credential Manager, macOS Keychain, the Secret Service over D-Bus on Linux). `reli` never writes it to a file or a log; while running it is held in ordinary process memory (not locked or zeroed), so swap, hibernation files or crash dumps may contain it (§4). |
| D | Approval gate. | TTY prompt before any agent proposal executes. In non-interactive mode or without a TTY, the default is **reject**. The direct `reli write` / `read` / `ls` commands are not prompted: typing the command is the approval. |
| E | Privacy of the user. | Zero outbound network traffic from `reli` itself. The Python sidecar talks to Ollama on `127.0.0.1:11434` only: the host is hard-coded, and `OLLAMA_HOST`, proxy environment variables and HTTP redirects are ignored. Model downloads happen only when the user runs `ollama pull`. |

---

## 3. Vectors and mitigations

Every vector below has a test: path and content vectors in
`tests/red_team.rs`, audit-log vectors mainly in `src/kernel/store.rs` and
`src/kernel/audit.rs`, approval vectors in `src/approval.rs` and
`src/cli.rs`. Mitigations live in deterministic Rust code — the LLM critic
is a second layer only and **cannot** approve anything the engine
rejected.

### 3.1 Path-based attacks

| Vector | Mitigation |
|---|---|
| `..` traversal (`../../etc/passwd`) | `validate_write_path` rejects any `ParentDir` component before I/O. |
| Unicode homoglyph pseudo-traversal (`．．/…`) | Fullwidth dots are not parsed as `ParentDir`; the segment becomes a literal directory name inside the sandbox. Escape cannot succeed. |
| Absolute path (`/etc/…`, `C:\…`) | Rejected as `PathOutsideSandbox`. Windows drive-relative forms (`C:foo`) are rejected before normalization. |
| Windows extended-length prefix `\\?\` or device prefix `\\.\` | Rejected as `InvalidPath`. |
| NTFS alternate data streams (`file.txt:hidden`) | Any `:` in the filename segment on Windows is rejected. |
| Null byte injection (`foo.txt\0.jpg`) | Rejected as `InvalidPath`. |
| Deceptive names: control characters (CR/LF, ESC, C1), bidi overrides and isolates (`invoice\u202Efdp.exe`), zero-width characters, BOM, Unicode line separators | Rejected as `InvalidPath` for every tool, before any other rule and before I/O, so such a name can never be shown to the approver, created in the sandbox or listed later. The same character set is escaped whenever the CLI prints text of external origin. |
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
| Planted trigger, view, extra table or virtual table in `audit.db` (e.g. `RAISE(IGNORE)` turning every INSERT into a silent no-op), including disguised ones (`type = 'TRIGGER'` or `'trigger' || char(0)`, which SQLite still loads as a trigger) | Strict allow-list of the schema, compared byte for byte: only the tables `audit_entries` and `schema_meta` (plain `CREATE TABLE`) and indexes on them; anything else is `AuditCorrupted` before any query touches the data. Every connection also runs with `trusted_schema = OFF`, `SQLITE_DBCONFIG_DEFENSIVE`, `cell_size_check` and a 1 MiB limit per value. Every INSERT must report exactly one written row. |
| Editing or adding columns that look meaningful but are not signed (e.g. a `path` column with a plausible value) | `audit_entries` must have exactly the v1 or v2 columns, none hidden or generated. `status_reason` must be NULL for `pending`/`ok` and non-NULL for `error`/`rejected`; anything else is `AuditCorrupted`. `reli log` only exports the signed columns, under fixed names. |
| Forcing the destructive v1→v2 migration on a v2 log (setting `schema_version` back to `1`) | Refused when the table already has v2 columns; a real v1 log is backed up (`audit.db.schema1.bak`) before migrating. |
| Replay: insert a duplicate `sequence_no` | SQLite `UNIQUE` / `PRIMARY KEY` constraint rejects it at INSERT time; even if injected via raw SQL, the chain re-verification fails. |
| Clock rollback or past-timestamp forgery | Timestamp is inside the HMAC input; any change breaks the chain. Ordering is enforced by `sequence_no`, not the clock. |
| Wrong HMAC key on reopen (including deleted keyring entry) | Re-verification fails with `AuditCorrupted`. |
| Side effect with no log entry (crash, power loss or log failure between acting and logging) | **Log before act:** a `pending` entry is committed with `synchronous = FULL` (plus `fullfsync` on macOS), and its anchor line and head witness are written, before approval and execution; if any of that fails, nothing runs. A `pending` left without outcome is closed as `error`/`abandoned` ("may or may not have run") by the next session, which names it on the terminal. |
| Two `reli` processes racing on the log (or one closing the other's in-flight `pending` as abandoned) | The database is opened with an exclusive file lock; a second process (including `reli reset`) waits about 2 s and exits with code `6`. |
| Forged or inconsistent outcome (resolving a non-pending row, resolving twice, outcome for different args) | Checked by `verify()` for every v2 row, plus a `UNIQUE` index on `resolves_seq`. Only possible at all with the HMAC key. |
| Acting on, or destroying evidence in, a log that fails verification | **Read-only mode:** every command that would act refuses (exit `3`) and names the first bad entry. `reli log` exports the rows as stored and then reports where verification fails. It uses a read-only SQLite connection with no checkpoint on close and refuses to open files SQLite would rewrite even when reading (a pending journal, a WAL next to an empty database); it never migrates, closes orphans, writes anchors or witnesses, or creates a key. Its output escapes control and invisible characters as JSON. Nothing is repaired automatically and no flag overrides it (`reset --force` only skips the `WIPE` prompt). |
| Another local account reading the log (paths and times of everything the agent did) | On Linux/macOS the audit directory and its `anchors/` are created `0700`, and `reli` warns when an existing audit directory is readable or writable by others. On Windows the default directory inherits the profile's private ACL; a custom `--audit-dir` does not (residual, see §4). |

### 3.4 Orchestration / approval attacks

| Vector | Mitigation |
|---|---|
| Non-interactive run silently auto-approving | Default in non-TTY / `--non-interactive` mode is **reject**, recorded as `rejected` / `non_interactive`. |
| Stalled operator blocking a batch | 60-second timeout; on expiry the proposal is rejected (`timeout`), not approved. |
| Rejected proposals leaving no trace | Every proposal that reaches the kernel is logged as `pending` before the prompt; refusals are logged as `user_denied`, `timeout` or `non_interactive`. Proposals the critic rejects, malformed proposals and `--dry-run` never reach the kernel and are not logged. |
| A human approving (or hiding) a rule-violating proposal | Path and size rules run **before** the prompt; a violation is logged as `rejected` / `policy: …` and the human is not asked. |
| Using the log as a data channel (an LLM-chosen path stored in clear) | Arguments are only stored as `args_hash`; refusal reasons are fixed codes (`policy: path_outside_sandbox`, `io: NotFound`, …), never the path or OS error text. |
| Orchestrator forging a proposal as "already approved" | The Rust kernel owns the approval gate; the Python side can only *propose*. |
| LLM critic "approving" a rule-violating action | Both critics run in the sidecar *before* the proposal reaches the kernel and can only reject; whatever they pass still goes through the Rust policy engine and the TTY gate. A critic approval never overrides a hard-rule rejection. |

---

## 4. Residual risk

These are things ReliAgent v0.1.0 does **not** fully defend against.
They are documented here so no user is surprised.

- **Code execution as the user.** If an attacker runs arbitrary code as the
  user account, they can read the HMAC key and forge or rewrite log entries,
  replace the binary on disk, or intercept TTY approvals. This is the
  classic threat-model boundary of any user-space policy kernel.
- **Supply-chain compromise.** A malicious Rust crate, Python runtime or
  Ollama binary can undermine everything above. Mitigations: pinned
  versions, `cargo --locked` in CI, a sidecar with no third-party Python
  dependencies, SBOM + `cosign` signature on releases. The bundled
  python-build-standalone runtime is pinned by SHA-256 in
  `scripts/pbs.lock` and checked before extraction; those digests were
  copied from the upstream release's `SHA256SUMS` over HTTPS, so they are
  only as trustworthy as that release was when it was pinned.
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
- **Linux without a Secret Service.** v0.1 has no fallback: `reli`
  refuses to run rather than keep the HMAC key in a weaker place. Any
  future file-based fallback would be an explicit, documented downgrade
  (`KNOWN_ISSUES.md`).
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
- **The release folder is part of the trusted computing base.** `reli`
  runs the interpreter in its `python/` folder, which runs the sidecar
  from its `site-packages`. On Linux/macOS `reli` refuses that folder if
  any directory of the runtime's `lib/python3.*` tree, the real
  interpreter or any entry of the `reliagent_python` package is not owned
  by the owner of `reli` (or root), is writable by group or others, or
  (inside the package) is a symlink. Standard-library files are covered
  only through their directories (nobody else can add or swap a module),
  not one by one. On Windows ACLs are
  not checked. Anyone who can write the folder (or set `RELI_PYTHON` /
  `--python`, which skip the check) runs code as the user — the same
  power as replacing `reli` itself.
- **Network file systems.** SQLite's file locks are unreliable on SMB/NFS.
  Keep `~/.reliagent/` on a local disk; on a network share two `reli`
  processes could race despite the exclusive lock.
- **`args_hash` is an unkeyed hash.** It is SHA-256 of
  `{"path":…,"bytes":…}`, so anyone holding the log or a `reli log`
  export can confirm a guessed path. The log keeps paths out of plain
  text, not out of reach of guessing.
- **Audit directory ACLs on Windows.** `reli` sets no ACL of its own: a
  custom `--audit-dir` outside the user profile inherits its parent's
  permissions, which may let other local users read or modify it.
- **First-run key race.** Two `reli` processes that both find no HMAC
  key at the same moment may each create one; one log then never
  verifies (fail closed, but unusable).
- **The HMAC key in memory.** While `reli` runs, the key is ordinary
  process memory: the OS may page it to swap or a hibernation file, and a
  crash dump may contain it.
- **Look-alike letters.** Letters from other scripts that look like Latin
  ones (Cyrillic "а" for "a") are accepted in file names; only control and
  invisible characters are refused.
- **Names that look alike but are not control characters.** Unicode
  normalization variants (NFC vs NFD) and, on Windows, names ending in a
  dot or a space are accepted as given.
- **SHA-256 collision resistance.** Treated as cryptographically sound in
  2026; a break in SHA-256 would invalidate the chain.

---

## 5. Out of scope (by policy)

- Root / administrator privilege escalation.
- Physical attacks (cold-boot, DMA, evil-maid, TPM bypass if no TPM is
  configured).
- Malicious behaviour inside the user's own legitimate process tree.
- Non-audited Ollama or model versions. Each release names the Ollama
  versions whose network behaviour was audited (`audits/`); the sidecar
  warns on any other version, which runs at the user's risk until
  re-audited.
- Ollama's own outbound traffic. With default settings the audited
  version contacts `ollama.com` (model recommendations, cloud catalogue);
  `OLLAMA_NO_CLOUD=1` or a firewall rule stops it
  ([`audits/ollama_v0.31.2.md`](../audits/ollama_v0.31.2.md)). ReliAgent
  does not start or configure Ollama.
- Bugs in CPython, Rust stdlib, or `rusqlite` / `cap-std` / `hmac` /
  `sha2`. These are treated as trusted computing base.

---

## 6. Change control

- This file is part of the repository and versioned alongside the code.
- Any PR that weakens a claim here must update this file in the same
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
- `tests/red_team.rs` — the path and content vectors of §3 as tests (the
  audit-log and approval vectors are tested next to their code).
