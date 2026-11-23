# `scripts/` — release packaging

These scripts turn a built `reli` binary into a self-contained release
directory. They are **not** needed for development: the project builds and
tests without them (see [CONTRIBUTING.md](../CONTRIBUTING.md)).

All of them are bash and portable: Linux, macOS (bash 3.2+) and Git Bash on
Windows. The release workflow ([`.github/workflows/release.yml`](../.github/workflows/release.yml))
runs `package_release.sh` on every platform.

## What lives here

| File | Purpose |
|---|---|
| `pbs.lock` | The pinned [python-build-standalone](https://github.com/astral-sh/python-build-standalone) release: tag, Python version, archive flavour and one SHA-256 per Rust target triple. Single source of truth for the bundled runtime. |
| `fetch_pbs.sh <triple> <dest>` | Downloads the pinned archive for one target into `vendor/cache/`, checks its SHA-256 against `pbs.lock` and only then extracts it to `<dest>`. |
| `package_release.sh <triple> <reli-binary> <out>` | Builds `<out>/`: the binary, `python/` (via `fetch_pbs.sh`) with the `reliagent_python` sidecar installed into its `site-packages`, and the user-facing docs (only files tracked by git, when run from a checkout). Smoke-tests a throwaway copy with `RELI_PYTHON` unset (`reli ping` must report the bundled interpreter, then a mock dry run), then fails if any path of the build machine (checkout, output, home, cargo and rustup homes) is found inside the bundle. |
| `release_rustflags.sh` | Prints `CARGO_ENCODED_RUSTFLAGS` with `--remap-path-prefix` for the cargo home, the target dir and the checkout, so the binary does not carry them (rustc records them for panic messages). |

`reli` finds `python/` next to its own executable, so the output directory
works as is once extracted. The sidecar has no third-party dependencies:
installing it means copying the package — no pip, no network beyond the
runtime download.

```bash
CARGO_ENCODED_RUSTFLAGS="$(bash scripts/release_rustflags.sh)" cargo build --release --locked
bash scripts/package_release.sh x86_64-pc-windows-msvc target/release/reli.exe dist/reli
dist/reli/reli.exe ping
```

Without the remapping, `package_release.sh` stops: the binary would carry
paths such as `C:\Users\<name>\.cargo\registry\...`.

## Invariants

1. **Pinned and verified.** Nothing is extracted unless the archive matches
   the SHA-256 in `pbs.lock`. Downloads are HTTPS-only and land in
   `vendor/cache/<archive>.part`; they become the cached archive only after
   verification. A mismatching archive is moved to `*.mismatch` and the
   script fails (exit code `4`).
2. **No system changes.** No `sudo`, no writes outside `vendor/`, the
   chosen output directory and a temporary copy for the smoke test; no
   keyring access, no shell profile edits.
3. **Nothing of the build machine in the bundle.** The sidecar's `.pyc`
   files are compiled with a neutral path (`compileall -d`), the bundled
   interpreter runs with `-B` while packaging, the smoke test runs on a
   copy, and a final scan of every file fails the build if a local path
   is still there.
4. **Not writable by group or others.** Both scripts run with `umask 022`
   and `package_release.sh` ends with `chmod -R u+rwX,go-w`: on Linux and
   macOS `reli` refuses a bundled `python/` that other accounts can write
   (see [KNOWN_ISSUES.md](../KNOWN_ISSUES.md)).
5. **Network is limited to GitHub** (the python-build-standalone release
   assets). The model is not downloaded here: users run
   `ollama pull qwen2.5:7b-instruct-q4_K_M`, and `reli run` verifies it
   against [`../MODEL_SHA256.txt`](../MODEL_SHA256.txt).

## Bumping the bundled Python

The runtime only gets CPython security fixes when `pbs.lock` is bumped.
Pick a python-build-standalone release at least two weeks old, keep Python
3.12.x, copy the digests for every listed target from that release's
`SHA256SUMS`, and run `package_release.sh` on at least one platform before
tagging.

`PBS_LOCK=<file>` makes `fetch_pbs.sh` read another lock file; it exists to
test the mismatch path and is refused in GitHub Actions. Every field of
the lock is checked against its expected shape, and a key or target listed
twice is an error.

On Linux, building `reli` needs `libdbus-1-dev` and `pkg-config` (the
keyring's Secret Service backend); the release workflow installs them.
