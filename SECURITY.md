# Security Policy

ReliAgent is a security-oriented project. We take vulnerability reports
seriously and will treat yours as such — even during the Research Preview
phase, when the project is pre-1.0 and the threat model is still
evolving.

## Supported versions

During the Research Preview phase, security fixes land on the `main`
branch and are cut as point releases. We do not backport to prior tags.

| Version | Supported |
|---|---|
| `main` (unreleased) | Yes |
| `v0.1.x` | Yes (current) |
| Older commits | No — pre-release development history |

Once we exit Research Preview, this table will be replaced with a proper
per-version support window.

## What counts as a security issue

Anything that weakens a claim in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). Concretely:

- Any path input that escapes the sandbox and produces an actual
  filesystem side effect outside `~/ReliAgent_Sandbox/`.
- Any way to forge, reorder, delete, or silently modify an audit entry
  without `reli verify` detecting it.
- Any way to cause `write_file` / `read_file` / `list_dir` to act on a
  path not derivable from the logged `args_hash`.
- Any bypass of the approval gate (TTY prompt, timeout, non-interactive
  mode) that results in a side-effectful action without explicit
  approval.
- Any outbound network traffic from the `reli` Rust binary, or from the
  Python sidecar to any host other than `127.0.0.1:11434`.
- Any disclosure of the HMAC key by `reli` itself (a file, a log, an
  error message, the audit log). The key in process memory reaching swap
  or a crash dump is a known limitation (THREAT_MODEL.md §4).

Issues that are explicitly **not** security issues (see THREAT_MODEL.md
§5):

- Problems that require root / administrator privileges to reproduce.
- Problems caused by a process already running as the user (ptrace,
  memory dump, binary replacement on disk).
- Physical attacks (cold boot, DMA, evil-maid).
- Weaknesses in a dependency at the pinned version we ship; please
  report those upstream and we will track the fix.

If you are unsure which side of the line a finding falls on, err on the
side of reporting it privately — we'll figure it out together.

## How to report

Use GitHub's private vulnerability reporting — it is the only channel:

1. Open <https://github.com/neomikhe/ReliAgent/security/advisories/new>
   (or the repository's **Security** tab → **Report a vulnerability**).
2. Fill out the advisory form.

Only the maintainers can see the report. It gives us a private place to
discuss and fix it, a CVE workflow if one becomes relevant, and a clean
audit trail. There is no security email address.

Please include:

- A minimal reproducer. A failing red-team-style Rust test is ideal;
  shell commands or a short repro binary is fine.
- The commit SHA you reproduced against.
- Your platform (`reli --version`, plus `uname -sr` or `ver`). Please do
  not paste full `systeminfo` output: it includes host names and network
  addresses.
- Whether you believe a patch is urgent (active exploitation in the wild)
  or a defence-in-depth hardening.

Please do **not**:

- Open a public GitHub issue with exploit details before we have a fix.
- Run the reproducer against a system you do not own.
- Disclose third-party data obtained while reproducing.

## Our commitment

ReliAgent is maintained by one person during the Research Preview, so
these are targets we aim for, not guarantees:

- **Acknowledgement within 72 hours** of a report reaching us.
- **Triage within 7 days**: is it a vulnerability, is it a duplicate, what
  is the severity.
- **Fix + advisory** on a timeline that matches severity:
  - Critical (sandbox escape, log forgery): patch release within 14 days.
  - High (any other item from the "What counts" list): within 30 days.
  - Medium / Low: next scheduled release.
- **Credit** in the advisory and release notes, if you want it. We will
  ask before naming you publicly.
- No gag orders, no "please take it down" requests. The bar is a fix
  ships first, then you are free to publish.

## Encryption

We do not publish a PGP key. A private vulnerability report is visible
only to you and the maintainers, but it is stored by GitHub, not
end-to-end encrypted. If a detail is too sensitive even for that, say so
in the report and we will agree on a different way to share it.

## Scope clarification

Only the code in this repository is in scope. Vulnerabilities in:

- [Ollama](https://github.com/ollama/ollama) → report upstream.
- Qwen model weights / licence concerns → report to Qwen maintainers.
- The Rust crates we depend on (`cap-std`, `rusqlite`, `hmac`, `keyring`,
  etc.) → report upstream. If exploitable through ReliAgent, tell us too
  and we'll track the pin until the upstream fix is released.

---

Thank you for helping us make ReliAgent trustworthy. This is exactly the
signal Research Preview exists to collect.
