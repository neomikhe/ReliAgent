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
| `v0.0.x` | No — development milestones, superseded by `v0.1.0` |

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
- Any disclosure of the HMAC key outside the OS keyring (logs, error
  messages, swap files, crash dumps).

Issues that are explicitly **not** security issues (see THREAT_MODEL.md
§5):

- Problems that require root / administrator privileges to reproduce.
- Problems caused by a process already running as the user (ptrace,
  memory dump, binary replacement on disk).
- Physical attacks (cold boot, DMA, evil-maid).
- Weaknesses introduced by dependencies whose audited version we ship
  with; please report those upstream and we will track the fix.

If you are unsure which side of the line a finding falls on, err on the
side of reporting it privately — we'll figure it out together.

## How to report

**Preferred:** GitHub Security Advisories.

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Fill out the advisory form.

This gives us a private channel, a CVE workflow if one becomes relevant,
and a clean audit trail.

**Alternative:** Email `security@<project-domain>` (address added to the
repo before the first public release tag).

Please include:

- A minimal reproducer. A failing red-team-style Rust test is ideal;
  shell commands or a short repro binary is fine.
- The commit SHA you reproduced against.
- Your platform (`reli --version`, `uname -a` or `systeminfo`).
- Whether you believe a patch is urgent (active exploitation in the wild)
  or a defence-in-depth hardening.

Please do **not**:

- Open a public GitHub issue with exploit details before we have a fix.
- Run the reproducer against a system you do not own.
- Disclose third-party data obtained while reproducing.

## Our commitment

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

## PGP key

For extremely sensitive reports, we will publish a PGP public key as part
of the first public release. Until that key is posted here, use GitHub
Security Advisories (end-to-end encrypted by GitHub on your behalf).

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
