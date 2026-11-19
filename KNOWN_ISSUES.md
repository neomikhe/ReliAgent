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
If the AV touches a file `reli` wrote, the next `reli verify` will flag
the sandbox contents as "modified outside the chain" — which is **true**
at the file-system level but not the action we care about.

- **Workaround:** Add `~/ReliAgent_Sandbox/` to your AV exclusion list.
- **Non-workaround:** Do **not** add `~/.reliagent/` to the exclusion
  list. That directory holds the audit DB and keyring-derived state;
  making AV blind to it would weaken detection of a real compromise.

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

The first `record()` call triggers a Keychain access prompt ("reli wants
to use the keychain"). This is expected; grant "Always Allow" to avoid
prompts on every action. The keychain entry is named `reliagent` /
`hmac-v1`.

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
