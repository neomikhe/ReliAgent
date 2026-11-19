# Known Issues — ReliAgent v0.1.0

This is a Research Preview. The issues below are expected, known, and
documented here rather than hidden behind silent workarounds.

If you hit something that is **not** in this list, please open an issue —
that is exactly the signal we are looking for in this phase.

---

## Windows

### Windows Defender / SmartScreen warnings on first run

The release binary is currently **unsigned**. Windows Defender SmartScreen
will show a blue "Windows protected your PC" dialog on first run.

- **Why:** Code-signing certificates cost money and are issued per
  identity. A signed binary is tracked as a v0.2 milestone (investigating
  [SignPath.io](https://signpath.io/) for OSS).
- **Workaround:** Click "More info" → "Run anyway", or verify the release
  signature manually:
  ```bash
  cosign verify-blob --certificate reli.exe.cert --signature reli.exe.sig reli.exe
  ```
- **Trust model:** a SmartScreen bypass is not the same as trusting the
  binary. Verify the cosign signature against our GitHub OIDC identity.

### Antivirus touching the sandbox

Some AV tools (Defender, Kaspersky, Bitdefender, CrowdStrike) actively
rewrite or quarantine files inside user directories for threat analysis.
`reli verify` does **not** notice: the audit log records which actions
ran and with what outcome, not the contents of the sandbox. A file you
find changed or missing may have been touched by the AV, not by `reli`.

- **Workaround:** Add `~/ReliAgent_Sandbox/` to your AV exclusion list if
  you need the sandbox to stay exactly as `reli` left it.
- **Non-workaround:** Do **not** add `~/.reliagent/` to the exclusion
  list. That directory holds the audit DB and anchors; making AV blind to
  it would weaken detection of a real compromise.

### `MAX_PATH` (260 characters)

Windows APIs fall back to a 260-character limit unless extended-length
paths (`\\?\`) are used. We **reject** `\\?\` on purpose (see
[THREAT_MODEL.md §3.1](docs/THREAT_MODEL.md#31-path-based-attacks)), so a
write under deeply-nested directories inside the sandbox can fail with an
I/O error even though the sandbox itself is well below any quota.

- **Mitigation:** `cap-std` uses long paths internally on Windows 10+;
  the failure mode is a clean `Io` error, not silent corruption. If you
  see this in practice, shorten the target path or open an issue with
  the failing path.

### Case-insensitive file system

NTFS is case-insensitive by default. Path validation happens before case
normalisation, so `Sandbox/../outside.txt` is rejected whether the user
types `Sandbox` or `sandbox`. This is a correctness *feature*, but it
means the literal byte string of the path matters for the audit log —
two sessions writing to `notes.TXT` and `notes.txt` will produce
different `args_hash` entries even though they hit the same file.

---

## macOS

### Gatekeeper warning on first run

Same class of issue as Windows SmartScreen. The binary is not notarised
in v0.1.0.

- **Workaround:** `xattr -d com.apple.quarantine reli` after download, or
  right-click → Open → confirm once.
- **Planned:** Apple Developer ID signing and notarisation are tracked
  for v0.2.

### Keychain prompts

The first command that opens the audit log triggers a Keychain access
prompt ("reli wants to use the keychain"). This is expected; grant
"Always Allow" to avoid prompts on every action. The keychain entry is
named `reliagent` / `audit-hmac-v1`.

---

## Linux

### `libsecret` may be missing on minimal distributions

The `keyring` crate uses the Secret Service API (gnome-keyring or kwallet
via `libsecret`). On headless servers, minimal containers, or very slim
distros you may see:

```
keyring error: platform secure storage failure: SS: NoKeyringDaemon
```

- **Workaround in v0.1:** install `libsecret-1-0` (Debian/Ubuntu),
  `libsecret` (Arch), or equivalent. A gnome-keyring daemon must be
  running (`dbus-run-session -- ...`).
- **Planned fallback (v0.2):** an encrypted file at `~/.reliagent/hmac.enc`
  with permissions `0600`, derived from a passphrase on first run. This
  is a strict downgrade versus the native keyring — documented as such
  and gated behind a `--no-keyring` flag.

### Flatpak / Snap confinement

Running `reli` inside a Flatpak sandbox that denies `~/ReliAgent_Sandbox`
access will cause every `write_file` to fail with `Io`. ReliAgent's own
sandbox is not compatible with an outer sandbox that hides the home
directory. Use the native binary.

---

## Audit log

### One `reli` at a time

The audit database is opened with an exclusive lock for the whole command
(including the 60 s approval prompt of `reli run`). A second `reli` —
including `reli reset` — started meanwhile waits about 2 s and exits with
code `6` ("audit log is in use"). Code `6` never means tampering; code `3`
does (or another audit/keyring failure). Other tools that open `audit.db`
(`sqlite3`, the verifier in [HASH_FORMAT.md](docs/HASH_FORMAT.md)) are
blocked too and use their own timeouts: run them while `reli` is not
running, or on a copy of the files.

Keep `~/.reliagent/` on a local disk. SQLite's locks are unreliable on
network file systems (SMB, NFS).

### `abandoned` entries

If `reli` is killed (Ctrl+C, crash, power loss) between logging an action
as `pending` and logging its outcome, the next `reli` that records an
action closes it as `error` with reason `abandoned: …` and prints its
sequence number, tool and time. Check the sandbox by hand for those: the
action may or may not have run. `reli verify` and `reli sandbox status`
list actions still waiting for that.

### Head witness in the OS keyring

Next to the HMAC key, `reli` keeps one keyring entry per audit log
(`reliagent` / `audit-head-v1:<16 hex chars>`, derived from the log's
path) holding the sequence number and HMAC of the last entry. It is
updated twice per action. A log that is shorter than its witness — tail
rows deleted, or `audit.db` deleted or replaced — fails verification
(exit code `3`).

- **Deleting `~/.reliagent/` by hand now looks like tampering.** Use
  `reli reset --wipe-everything`, which also removes the witness.
- Using several `--audit-dir` values creates one witness per directory;
  `reli reset` with the same `--audit-dir` removes it.
- Restoring an old backup of `~/.reliagent/` fails verification for the
  same reason. Restore it only together with `reli reset`, or after
  removing that log's witness entry from the keyring.

### One-way upgrade of the log format

Opening an existing audit log with this version migrates its schema to
version 2 (log format v2: `pending` + outcome per action). Old entries are
kept and still verify, and the original database is first copied to
`~/.reliagent/audit.db.schema1.bak`. An older `reli` binary will refuse
the migrated database ("unsupported schema version"); use the backup to
go back.

### Durability costs a little time

Each action commits two entries with `synchronous = FULL` (a disk flush
each; `F_FULLFSYNC` on macOS), so the log survives power loss. Expect a
few milliseconds per action on an SSD, more on slow disks.

### `reli read` on a terminal

When stdout is a terminal, `reli read` escapes control characters (escape
sequences, `\r`, …) and replaces invalid UTF-8, because the file may have
been written by the model. Newlines and tabs are kept. Pipe or redirect
the output (`reli read a.bin > a.bin`) to get the exact bytes.

---

## Model and dependencies

### The model comes from Ollama and is verified on every run

ReliAgent does not download model weights. You fetch them with Ollama:

```bash
ollama pull qwen2.5:7b-instruct-q4_K_M
```

[`MODEL_SHA256.txt`](MODEL_SHA256.txt) pins the SHA-256 of that tag's
weights layer as published on `registry.ollama.ai`. Before any inference,
`reli run`:

1. asks Ollama (`/api/show`) which blob it serves the tag from, and refuses
   unless the Modelfile has exactly one `FROM`, no `ADAPTER`, and the blob
   digest is the pinned one;
2. refuses unless the blob path is a local absolute path inside a `blobs/`
   directory (UNC and device paths are rejected before touching the file
   system);
3. re-computes the SHA-256 of that blob file on disk (~5 s for 4.7 GB on an
   SSD) and refuses on mismatch.

Limits of this check, stated plainly:

- **Only the weights are pinned.** Ollama's prompt template, system prompt
  and default parameters for the tag are separate layers and are not
  verified.
- **It verifies a file, not the server.** If Ollama is not running, any
  local account can listen on `127.0.0.1:11434`, pass the check by
  pointing at the genuine blob, and receive your prompts. It still cannot
  bypass the policy engine or the approval prompt. See
  [THREAT_MODEL.md §4](docs/THREAT_MODEL.md#4-residual-risk).
- **Time-of-check gap.** If Ollama already has the model loaded in memory
  (it keeps it for a few minutes after use), a blob swapped *and then
  reverted* between runs would not be noticed, nor would a re-tag between
  the check and the inference. Re-hashing every run makes this window
  small, not zero.
- **The blob must be readable by your user.** Linux service installs keep
  models under `/usr/share/ollama/.ollama/models`, owned by the `ollama`
  user. If your user cannot read the blob, `reli run` stops with a
  model-integrity error rather than skipping the check. Grant read access
  to the blob or run Ollama as your user.
- `reli run --mock-llm` skips Ollama and the model entirely (deterministic
  test agent). Use it only for demos and tests.

### Model licence

Qwen2.5-7B-Instruct is published under the
[Apache License 2.0](https://huggingface.co/Qwen/Qwen2.5-7B-Instruct/blob/main/LICENSE),
the same licence as ReliAgent; Ollama ships that licence text as a layer of
the tag. Other Qwen2.5 sizes (e.g. 3B, 72B) use different licences — if
you change the canonical model, re-check its terms.

### CPU-only inference is slow

On a machine without a supported GPU, one `reli run` (agent + LLM critic,
two inferences) takes about a minute with the 7B model. This is Ollama's
inference speed, not ReliAgent overhead.

### Ollama telemetry

Ollama has historically contacted `ollama.com` for version checks. We
verify this on the version we target and record the audit in
`audits/ollama_vX.Y.Z.md`. **Newer Ollama versions ship at your own risk
until we re-audit.** If you are privacy-sensitive, pin the audited
version.

### No outbound network from `reli` itself

The Rust binary makes **zero** outbound network calls. The Python sidecar
only speaks to `http://127.0.0.1:11434` (Ollama's loopback interface): the
host is hard-coded, and `OLLAMA_HOST`, proxy variables (`HTTP_PROXY`,
`ALL_PROXY`, ...) and HTTP redirects are ignored on purpose. To use Ollama
on another port or machine you would have to change the code — that is
by design. Model downloads happen only when you run `ollama pull`
yourself. If you see `reli` making any other network call, that is a bug —
please report it as a vulnerability (see [`SECURITY.md`](SECURITY.md)), not
as a regular issue.

---

## v0.1-specific limitations (by design)

These are not bugs; they are scope for later milestones. Documented here
so users do not mistake them for regressions.

| Limitation | Planned in |
|---|---|
| No per-session file quota enforcement (`SessionQuotaExceeded`). | v0.2 |
| No `grant_scope` tool (pre-approval with duration + path prefix). | v0.2 |
| `args_hash` is **not** JCS-canonical (RFC 8785). | v0.2 |
| No read allowlist for paths outside the sandbox (today: blanket deny). | v0.2 |
| No Tauri GUI. CLI only. | v0.2+ |
| No code-execution tool (`execute_code`). | v0.3 (WASI-Python / RustPython) |
| No HTTP tool (`http_get`) with domain allowlist. | v0.2 |
| Windows code-signing certificate. | v0.2 |
| macOS notarisation. | v0.2 |

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for which of these are
security limitations and which are ergonomics limitations.

---

## Reporting new issues

Open a GitHub issue with:

1. `reli --version` and OS version.
2. The command you ran and the full stderr output.
3. Whether you can reproduce it on a fresh sandbox (`reli reset
   --wipe-everything` then retry).

For anything you believe is a security issue, see
[`SECURITY.md`](SECURITY.md) instead.
