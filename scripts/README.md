# `scripts/` — packaging and release helpers

These scripts are the one-shot helpers that turn a source checkout into a
distributable release. They are **not** required for development — the
project builds and tests fine without ever running anything here.

## What lives here

| Script | Purpose |
|---|---|
| `fetch_pbs.sh` / `fetch_pbs.ps1` | Download a matching [python-build-standalone](https://github.com/astral-sh/python-build-standalone) tarball and verify its checksum. The bundled Python lives at `vendor/python/` and is consumed by `reli` as `--python` when available. |
| `fetch_model.sh` / `fetch_model.ps1` | Download the canonical Qwen2.5 GGUF weights, verify the SHA-256 against [`../MODEL_SHA256.txt`](../MODEL_SHA256.txt), and print the Qwen licence URL the user must accept. Resumable via HTTP `Range`. |
| `verify_release.sh` | After `cosign verify-blob` succeeds, cross-checks the SBOM against the installed file list. |

## Invariants

1. **No script mutates system state outside the repo.** Downloads land
   in `vendor/` (git-ignored). Scripts never invoke `sudo`, never write
   outside the working tree.
2. **Every download is hash-checked before use.** A mismatch is a hard
   stop — the script must not proceed with a partial or unverified
   file. Partial downloads are kept on disk so a retry can resume via
   `Range`, never silently discarded.
3. **Network is the only side effect.** No daemons, no keyring writes,
   no shell profile edits.

## Status

v0.1.0 ships the scripts as **scaffolding**. Exact upstream URLs and the
Qwen SHA-256 in `MODEL_SHA256.txt` are placeholders — replace before
cutting a public release. The release workflow at
`.github/workflows/release.yml` calls these scripts for the signed
artifact build, so edits here must keep them CI-compatible (exit
non-zero on failure, stdout machine-parseable).
