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
- **Workaround:** verify the archive first, then click "More info" →
  "Run anyway". What is signed is the archive (`.zip`), not `reli.exe`;
  the exact identity for each tag is in the release notes:
  ```bash
  cosign verify-blob \
      --certificate reli-v0.1.0-windows-x86_64.zip.cert \
      --signature   reli-v0.1.0-windows-x86_64.zip.sig \
      --certificate-identity "https://github.com/<owner>/<repo>/.github/workflows/release.yml@refs/tags/v0.1.0" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      reli-v0.1.0-windows-x86_64.zip
  gh attestation verify reli-v0.1.0-windows-x86_64.zip --repo <owner>/<repo>
  ```
- **Trust model:** a SmartScreen bypass is not the same as trusting the
  binary. Always pass the exact `--certificate-identity`: without it,
  cosign would accept a signature from *any* GitHub workflow.

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

- **Workaround:** after verifying the cosign signature, clear the
  quarantine flag on the whole extracted folder (it also covers the
  bundled `python/`): `xattr -dr com.apple.quarantine reli-v0.1.0-macos-aarch64`.
- **Planned:** Apple Developer ID signing and notarisation are tracked
  for v0.2.

### Keychain prompts

The first command that opens the audit log triggers a Keychain access
prompt ("reli wants to use the keychain"). This is expected; grant
"Always Allow" to avoid prompts on every action. The keychain entry is
named `reliagent` / `audit-hmac-v1`.

---

## Linux

### The keyring needs D-Bus and a Secret Service daemon

On Linux the `keyring` crate talks to the Secret Service API over D-Bus
(gnome-keyring, KeePassXC or KWallet's Secret Service provider). The
`reli` binary links `libdbus-1.so.3`, present on almost every desktop
distribution; minimal containers need the `libdbus-1-3` package (Debian/
Ubuntu) or `dbus-libs` (Fedora) to start at all. Building from source also
needs the headers and `pkg-config` (`libdbus-1-dev pkg-config` on
Debian/Ubuntu, `dbus-devel pkgconf` on Fedora).

On headless servers, minimal containers, or very slim distros with no
Secret Service running you may see:

```
keyring error: platform secure storage failure: SS: NoKeyringDaemon
```

- **Workaround in v0.1:** install and start a Secret Service provider,
  e.g. `gnome-keyring` inside a D-Bus session
  (`dbus-run-session -- ...`).
- **No fallback in v0.1:** without a Secret Service `reli` refuses to
  run (exit code `3`) instead of keeping the HMAC key somewhere weaker.
  A file-based fallback is still an open question for v0.2; if it comes,
  it will be opt-in and documented as a downgrade.

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

### A log that fails verification: read-only mode

When verification fails, `reli` names the first bad entry and from then
on every command that opens the log refuses to run (exit code `3`):
`run`, `write`, `read`, `ls`, `verify` and `sandbox status`. Nothing is
repaired automatically and there is no `--force`. What still works:

- `reli log > export.jsonl` prints every entry exactly as stored (also
  the tampered ones) and then says on stderr where verification fails.
  It reads through a read-only connection without a checkpoint on close,
  so it never modifies the log, creates a key, anchor or witness, or
  migrates an old database (SQLite may leave an empty `audit.db-shm`
  next to it).
- `reli reset --wipe-everything` starts over once you have what you need.

`reli log` refuses to export, and asks you to analyse a copy instead,
when the database contains anything `reli` never creates (a view, a
trigger, another table, an extra column, a value over 1 MiB), or when
SQLite would rewrite the files just to read them (a pending
`audit.db-journal`, or an `audit.db-wal` next to an empty `audit.db`).
Copy the whole audit directory before investigating further.

While `reli log` is reading — for example piped into a pager — other
`reli` commands report the log as in use (exit code `6`).

Before sharing an export, note that `args_hash` is a plain SHA-256 of
`{"path":…,"bytes":…}` ([HASH_FORMAT.md §3](docs/HASH_FORMAT.md)): a
path that can be guessed can be confirmed from it.

### Audit files are private on Linux and macOS

`reli` creates the audit directory (`~/.reliagent/` by default) and its
`anchors/` with mode `0700`: the log holds the paths and times of
everything the agent did. A directory that already existed keeps its
mode; `reli` warns when other users can read or write it (run `chmod 700`
on it, e.g. if an older build created it).

On Windows the default `%USERPROFILE%\.reliagent` inherits the private
permissions of your profile, but `reli` sets no ACL of its own: a custom
`--audit-dir` inherits whatever its parent allows (directly under `C:\`,
for instance, every local user may modify subfolders). Keep the audit
directory inside your profile.

### The very first run creates the HMAC key

The key is created the first time any `reli` command needs it. Two
`reli` processes started at exactly that moment on a machine with no key
yet may each create one; the log of the one that lost then never
verifies. Run the first command on a new machine on its own.

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

### `reli read` and `reli log` on a terminal

When stdout is a terminal, `reli read` escapes control characters (escape
sequences, `\r`, …) and replaces invalid UTF-8, because the file may have
been written by the model. Newlines and tabs are kept. Pipe or redirect
the output (`reli read a.bin > a.bin`) to get the exact bytes. `reli log`
always writes control and invisible characters as JSON escapes, on a
terminal or not (the log may have been tampered with), so its output is
valid JSON Lines that is safe to `cat`, `grep` or `jq` later.

### File names with control or invisible characters are refused

Paths containing control characters (including tab and newline) or
characters that render as nothing — bidi controls such as U+202E,
zero-width characters and joiners, the soft hyphen, Hangul fillers,
variation selectors, invisible "tag" characters (U+E0000 block, which a
model reads but a human does not see), a BOM or Unicode line separators —
are rejected for every tool (`invalid path`). The agent can neither
create nor read such a file, and a name can never look different in the
approval prompt from what it is. Rename files like that by hand if you
need `reli` to reach them.

Ordinary Unicode (accents, CJK, most emoji) is fine. The cost: names that
need a joiner or a variation selector are refused too: emoji written
with a variation selector (the red heart) or a zero-width joiner
(family or profession sequences), and some Persian, Urdu or Indic names.

Not covered: two names that differ only in Unicode normalization (NFC
vs NFD "café") are different files on Windows and Linux and look the
same; on Windows, names ending in a dot or a space are created as given,
and other Windows tools later strip that ending.

---

## Bundled Python runtime

### Security fixes arrive only with a new pin

Releases ship CPython from python-build-standalone, pinned by tag and
SHA-256 in [`scripts/pbs.lock`](scripts/pbs.lock) (v0.1.0: Python 3.12.16,
release `20261026`). It does not update itself: a CPython security fix
reaches users only when the pin is bumped and a new release is cut. The
sidecar only uses the standard library and talks to `127.0.0.1`, which
limits the exposure, but check the pinned version before relying on it.

### Keep `python/` next to `reli`

`reli` looks for `python/` in the directory of its own executable. Moving
the binary alone (e.g. to `/usr/local/bin`) makes it fall back to the
`python3` in `PATH`, which normally does not have the sidecar installed;
`reli ping` then fails with a hint. Move the whole folder, or symlink the
binary (symlinks are resolved to the real location).

The order is `--python`, then `$RELI_PYTHON`, then the bundled `python/`,
then `PATH`: a `RELI_PYTHON` left over from a source checkout **wins over
the bundled runtime**. `reli ping` and `reli run` print which interpreter
they use and why (`[reli] sidecar: <path> (<source>)`).

### The release folder is trusted code

`reli` runs whatever interpreter sits in its `python/` folder, and that
interpreter runs the sidecar from its `site-packages`. Whoever can write to
that folder can run code as you. So:

- **Extract the archive as the user who will run `reli`**, into a
  directory only that user can write (e.g. under your home). The archives
  record owner `root`/uid 0, so extracting as root keeps root ownership
  instead of handing the files to an unrelated account.
- On Linux and macOS, `reli` refuses the bundled `python/` (and says so)
  if any checked entry is not owned by the owner of `reli` (or root), or
  is writable by group or others; it then falls back to `PATH`. Checked:
  `python/`, `python/bin/`, `python/lib/`, every directory under
  `python/lib/python3.*/` (`site-packages/` included), the real
  interpreter (symlinks resolved) and every file and directory of the
  installed `reliagent_python` package, which may not contain symlinks.
  Standard-library files are not checked one by one (there are
  thousands), but all their directories are, so no other account can add
  or swap a module.
- On file systems without POSIX permissions (FAT/exFAT drives, some
  network mounts, `/mnt/c` in WSL without `metadata`), every file looks
  writable by everyone, so the bundled `python/` is always refused.
  Extract onto a native file system instead. `--python <dir>/python/bin/python3`
  (or `RELI_PYTHON`) skips the check entirely: you vouch for that
  interpreter yourself.
- On Windows, ACLs are **not** checked: do not put the folder in a
  location other accounts can write to (e.g. `C:\ProgramData`, a shared
  drive).

### Size

Almost all of it is the Python runtime. Measured on the v0.1.0 build:
about 24 MB compressed and 63 MB extracted on Windows, 35 MB and 110 MB on
Linux (its runtime ships more shared libraries). The macOS archive has
not been measured outside CI yet.

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
| One action per `reli` process: each `run`, `write`, `read` or `ls` performs at most one action, so there are no multi-action sessions yet — hence no per-session file quota (`SessionQuotaExceeded`) and no session id in log entries (each action is still linked to its outcome through `resolves`). | v0.2 (sessions) |
| No `grant_scope` tool (pre-approval with duration + path prefix). | v0.2 |
| The approval prompt is `y/N` only. `always-for-this-path` arrives with `grant_scope`; `abort` would be the same as `N` while each run proposes a single action. | v0.2 |
| No read allowlist for paths outside the sandbox: reading outside is always refused, never offered for approval. | v0.2 |
| `args_hash` does not depend on how a proposal is spelled, but its bytes are not byte-exact RFC 8785 (JCS): `write_file` signs `path` before `bytes` (see [HASH_FORMAT.md §3](docs/HASH_FORMAT.md)). | Next hash format version |
| No configuration file: everything is a flag or an environment variable (`--sandbox`, `--audit-dir`, `--python`, `RELI_PYTHON`). | v0.2+ |
| No keyring fallback on Linux without a Secret Service (`reli` refuses to run). | Open question |
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
