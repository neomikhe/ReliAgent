# Contributing to ReliAgent

Thanks for looking. ReliAgent is in Research Preview, which means the
best contributions right now are the uncomfortable ones: adversarial test
vectors, platform weirdness, missed edge cases in the policy engine.

## Before you start

1. Read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). Every contribution
   must be compatible with the threat model — if yours isn't, the PR
   needs to change the threat model first, in the same commit, with
   rationale.
2. Read [`KNOWN_ISSUES.md`](KNOWN_ISSUES.md). Platform quirks listed
   there are expected, not bugs.
3. For anything that could be a vulnerability, use
   [`SECURITY.md`](SECURITY.md) — not a public PR or issue.

## What we actively want

- **Red-team vectors.** Adversarial paths, canonicalisation corner cases,
  weird Unicode, filesystem oddities (NTFS reparse points, APFS
  case-folding, `overlayfs`, FUSE), symlink TOCTOU scenarios on every
  OS. Add them to [`tests/red_team.rs`](tests/red_team.rs) following the
  existing pattern.
- **Bug reports with reproducers.** A failing test > a shell transcript >
  a screenshot > nothing.
- **Documentation fixes.** Including "this sentence in the README is
  technically true but confused me for 20 minutes."
- **Portability patches** for platforms we haven't exercised (BSDs,
  musl, Alpine, NixOS, macOS on Apple Silicon vs Intel).

## What we are cautious about

- **New tools.** `write_file`, `read_file`, `list_dir` are a deliberately
  tiny surface. Adding a tool means expanding the threat model. Open an
  issue first.
- **Network features.** ReliAgent deliberately has no outbound network
  from the kernel. `http_get` lives in the v0.2 plan with a domain
  allowlist; nothing sooner.
- **"Make it faster" patches that change the audit format.** Every
  change to the HMAC input needs a `hash_format_version` bump and a
  migration. We will not trade correctness for throughput.
- **Dependency additions.** We keep the dependency graph narrow and
  audited. A new crate in `Cargo.toml` needs a one-paragraph
  justification in the PR description.

## Dev setup

```bash
# Rust toolchain is pinned to 1.85.0 in rust-toolchain.toml
cargo --version
rustc --version

# Linux only: the keyring's Secret Service backend links libdbus
sudo apt-get install libdbus-1-dev pkg-config   # Fedora: dbus-devel pkgconf

# Python toolchain uses uv + Python 3.12; this installs the package
# (editable) and pytest into python-core/.venv
(cd python-core && uv sync --extra dev)

# Run reli against that venv
export RELI_PYTHON="$PWD/python-core/.venv/bin/python"   # Windows: .../.venv/Scripts/python.exe
```

To build and smoke-test a release-style bundle (binary + pinned Python
runtime + sidecar), see [`scripts/README.md`](scripts/README.md).

Run the full local check matrix before pushing:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --release -- -D warnings
cargo test                              # unit + integration (Rust)
cargo test -- --ignored                 # real sidecar bridge, needs venv
cd python-core && uv run pytest && cd ..
```

The bridge tests spawn `python` (Windows) or `python3` (elsewhere). If
that is not a real interpreter — e.g. the Microsoft Store alias on
Windows — point them at the venv:

```bash
RELI_TEST_PYTHON="$PWD/python-core/.venv/Scripts/python.exe" cargo test   # Windows (Git Bash)
RELI_TEST_PYTHON="$PWD/python-core/.venv/bin/python" cargo test           # Linux/macOS
```

If you move the checkout to another directory, run `cargo clean` and
re-create the venv (`rm -rf python-core/.venv && uv sync`): test binaries
embed the old absolute path and fail with "directory name is invalid".

None of the tests need Ollama; they use a local fake server.

`reli` starts the sidecar as `python -I -m reliagent_python` (isolated
mode: the current directory and `PYTHONPATH` are not on `sys.path`), so
the package must be installed in the interpreter you pass with
`--python` — `uv sync` in `python-core/` does that for the venv. To see
full Python tracebacks from the sidecar while debugging, set
`RELI_SIDECAR_DEBUG=1`; by default it only logs the exception type.

Red-team suite specifically:

```bash
cargo test --test red_team
```

If you add a vector, it must appear here with a passing (or documented
`#[ignore]`) entry.

## Coding conventions

- **Rust.** `cargo fmt` clean, `cargo clippy` clean at `-D warnings`.
  Public APIs carry short doc comments describing the invariant, not
  the implementation. New errors extend `KernelError` rather than
  stringly-typed messages.
- **Python.** `pytest` clean, type hints on public functions. Prefer
  small pure functions over classes where a module-level function
  suffices.
- **Tests.** Integration tests in `tests/`, unit tests alongside the
  code. Name red-team tests `vNN_short_description` and match them to
  the vector list in `PROJECT_CONTEXT.md §16` if possible.
- **Commits.** Conventional-ish: `feat:`, `fix:`, `docs:`, `test:`,
  `refactor:`, `chore:`. English. Imperative mood. Body wraps at 72
  columns.
- **Comments.** Explain *why*, not *what*. Don't leave breadcrumbs for
  removed code (no `// previously used by ...`). Names should do the
  "what" work.

## Pull request flow

1. Fork, branch, commit.
2. Run the check matrix above. A PR that fails CI on first push is
   expected occasionally, but please make sure it passes locally first.
3. Open the PR against `main`. Describe:
   - What the change does.
   - Why (especially if it touches the audit format or threat model).
   - How you tested it. If you added a test, which file / which vector.
   - Any threat-model implications.
4. Expect review. Security-adjacent changes go through two reviewers
   when possible.

## Commit signing

We plan to require signed commits once we exit Research Preview. For
now, signed commits are welcome but not required. The release artifacts
are signed with `cosign` regardless — see
`.github/workflows/release.yml`.

## Licence of contributions

By submitting a contribution, you agree that it is licensed under the
project's [Apache License 2.0](LICENSE). We do not require a separate
CLA at this stage; the Apache-2.0 contribution clause is sufficient.

## Code of Conduct

Participating in this project means agreeing to the
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). We enforce it.

## Questions that are not a PR yet

- File an issue with the `question` label.
- If it's a design question about the threat model or audit format,
  cross-reference the section of `docs/THREAT_MODEL.md` or
  `docs/HASH_FORMAT.md` you are asking about.

Thanks again. ReliAgent gets better every time someone on the outside
points out something we missed.
