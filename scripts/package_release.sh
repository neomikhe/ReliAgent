#!/usr/bin/env bash
# package_release.sh — assemble a self-contained release directory and
# smoke-test it.
#
# Usage: scripts/package_release.sh <rust-target-triple> <reli-binary> <out-dir>
#   e.g. scripts/package_release.sh x86_64-pc-windows-msvc \
#            target/x86_64-pc-windows-msvc/release/reli.exe dist
#
# Result:
#   <out-dir>/reli[.exe]
#   <out-dir>/python/          python-build-standalone runtime (scripts/pbs.lock)
#                              with reliagent_python in its site-packages
#   <out-dir>/README.md, LICENSE, SECURITY.md, KNOWN_ISSUES.md,
#   <out-dir>/MODEL_SHA256.txt, <out-dir>/docs/
#
# `reli` finds <out-dir>/python next to itself, so the directory works as is
# once extracted. The sidecar has no third-party dependencies: installing
# it is copying the package, no pip and no network beyond fetch_pbs.sh.
#
# The smoke test needs neither Ollama nor the OS keyring.

set -euo pipefail
# On Unix reli refuses a bundle that group/other can write (see
# check_bundle_trust in src/cli.rs): build it that way regardless of the
# caller's umask, and normalise the modes again at the end.
umask 022

if [[ $# -ne 3 ]]; then
    echo "usage: $0 <rust-target-triple> <reli-binary> <out-dir>" >&2
    exit 1
fi
TARGET_TRIPLE="$1"
RELI_BIN="$2"
OUT="$3"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ ! -f "${RELI_BIN}" ]]; then
    echo "[package] binary not found: ${RELI_BIN}" >&2
    exit 1
fi

rm -rf "${OUT}"
mkdir -p "${OUT}"
cp "${RELI_BIN}" "${OUT}/"

bash "${ROOT}/scripts/fetch_pbs.sh" "${TARGET_TRIPLE}" "${OUT}/python"
case "${TARGET_TRIPLE}" in
    *-windows-*) PY="${OUT}/python/python.exe" ;;
    *)           PY="${OUT}/python/bin/python3" ;;
esac

# Copy <repo-relative dir> to <dest>, only files tracked by git when this is
# a checkout (a local build must not ship stray untracked files). NUL
# separated, so no file name is mangled or split; an empty list, a symlink
# or a tracked file missing from the working tree is an error, not a
# smaller (or larger) bundle.
copy_tracked() {
    local src="$1" dest="$2" f rel count=0
    mkdir -p "${dest}"
    if ! git -C "${ROOT}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        cp -R "${ROOT}/${src}/." "${dest}/"
        return
    fi
    while IFS= read -r -d '' f; do
        # cp would copy the target of a symlink (any file of this machine)
        # into the bundle.
        if [[ -L "${ROOT}/${f}" ]]; then
            echo "[package] refusing to bundle a symlink: ${f}" >&2
            exit 1
        fi
        if [[ ! -f "${ROOT}/${f}" ]]; then
            echo "[package] tracked file missing from the working tree: ${f}" >&2
            exit 1
        fi
        rel="${f#"${src}"/}"
        mkdir -p "${dest}/$(dirname "${rel}")"
        cp "${ROOT}/${f}" "${dest}/${rel}"
        count=$((count + 1))
    done < <(git -C "${ROOT}" ls-files -z -- "${src}")
    if [[ "${count}" -eq 0 ]]; then
        echo "[package] no tracked files under ${src}" >&2
        exit 1
    fi
}

# Install the sidecar where `python -I` looks for it. -B on every call: the
# bundled interpreter must not write stdlib __pycache__ (with this
# machine's paths) into the bundle.
SITE="$("${PY}" -I -B -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])' | tr -d '\r')"
if command -v cygpath >/dev/null 2>&1; then
    SITE="$(cygpath -u "${SITE}")"
fi
copy_tracked python-core/src/reliagent_python "${SITE}/reliagent_python"
# -d: neutral path recorded in the .pyc files (and tracebacks) instead of
# this machine's; checked-hash: validity does not depend on file times.
"${PY}" -I -B -m compileall -q -d reliagent_python \
    --invalidation-mode checked-hash "${SITE}/reliagent_python"

# Minimal .dist-info so SBOM tools see the sidecar as an installed package.
SITE_NATIVE="${SITE}"
PYPROJECT="${ROOT}/python-core/pyproject.toml"
if command -v cygpath >/dev/null 2>&1; then
    SITE_NATIVE="$(cygpath -w "${SITE}")"
    PYPROJECT="$(cygpath -w "${PYPROJECT}")"
fi
"${PY}" -I -B - "${SITE_NATIVE}" "${PYPROJECT}" <<'PYEOF'
import base64, hashlib, pathlib, sys, tomllib

site, pyproject = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
project = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]
name, version = project["name"], project["version"]
info = site / f"{name.replace('-', '_')}-{version}.dist-info"
info.mkdir()

def write(path, text):
    path.write_bytes(text.encode("utf-8"))  # LF on every platform

write(info / "METADATA",
      "Metadata-Version: 2.1\n"
      f"Name: {name}\nVersion: {version}\n"
      f"Summary: {project.get('description', '')}\n"
      "License: Apache-2.0\n"
      f"Requires-Python: {project['requires-python']}\n")
write(info / "INSTALLER", "reliagent package_release.sh\n")
rows = []
for f in sorted([*(site / "reliagent_python").rglob("*"), *info.iterdir()]):
    if f.is_file():
        digest = base64.urlsafe_b64encode(hashlib.sha256(f.read_bytes()).digest())
        rows.append(f"{f.relative_to(site).as_posix()},sha256={digest.rstrip(b'=').decode()},{f.stat().st_size}")
rows.append(f"{info.name}/RECORD,,")
write(info / "RECORD", "\n".join(rows) + "\n")
PYEOF

cp "${ROOT}/README.md" "${ROOT}/LICENSE" "${ROOT}/SECURITY.md" \
   "${ROOT}/KNOWN_ISSUES.md" "${ROOT}/CHANGELOG.md" "${ROOT}/MODEL_SHA256.txt" "${OUT}/"
copy_tracked docs "${OUT}/docs"
# The README sends users to the Ollama audit (how to run Ollama offline).
copy_tracked audits "${OUT}/audits"

# Owner keeps rwX, nobody else may write (tar, cp and the PBS archive may
# have carried other modes). No-op on Windows file systems.
chmod -R u+rwX,go-w "${OUT}"

# --- Smoke test on a throwaway copy. ---------------------------------------
# Running Python writes __pycache__ (with this machine's paths) next to the
# stdlib; the bundle that ships must not contain them.
SMOKE="$(mktemp -d)"
trap 'rm -rf "${SMOKE}"' EXIT
cp -R "${OUT}/." "${SMOKE}/"
SMOKE_RELI="${SMOKE}/$(basename "${RELI_BIN}")"
echo "[package] smoke test"
# Without RELI_PYTHON, and checking the banner: the test must exercise the
# bundled interpreter, not whatever Python the build machine points to.
SMOKE_LOG="$(env -u RELI_PYTHON "${SMOKE_RELI}" ping 2>&1)" || {
    echo "${SMOKE_LOG}" >&2
    exit 1
}
echo "${SMOKE_LOG}"
if [[ "${SMOKE_LOG}" != *"(incluido junto a reli)"* ]]; then
    echo "[package] smoke test did not use the bundled interpreter" >&2
    exit 1
fi
env -u RELI_PYTHON "${SMOKE_RELI}" --non-interactive run --mock-llm --dry-run \
    "write 'hola' to smoke.txt"

# --- Nothing from the build environment inside the bundle. ----------------
OUT_ABS="$(cd "${OUT}" && pwd)"
# $HOME, CARGO_HOME and RUSTUP_HOME cover the registry and toolchain paths
# rustc records for panic messages.
BUILD_DIRS=("${ROOT}" "${OUT_ABS}" "${SMOKE}" "${HOME}"
            "${CARGO_HOME:-${HOME}/.cargo}" "${RUSTUP_HOME:-${HOME}/.rustup}")
NEEDLES=()
for p in "${BUILD_DIRS[@]}"; do
    NEEDLES+=("${p}")
    if command -v cygpath >/dev/null 2>&1; then
        NEEDLES+=("$(cygpath -w "${p}")" "$(cygpath -m "${p}")")
    fi
done
GREP_ARGS=()
for needle in "${NEEDLES[@]}"; do
    # A very short needle (HOME=/root, a drive root) matches by chance
    # inside unrelated binaries; the longer paths below it still catch it.
    if [[ ${#needle} -ge 8 ]]; then
        GREP_ARGS+=(-e "${needle}")
    fi
done
# No -i: some GNU grep builds (Git Bash 3.0) abort with -i -F on binary
# data. Exit status: 0 = found, 1 = clean, anything else = the check itself
# failed, which must not pass as "clean".
set +e
LEAKS="$(grep -rlaF "${GREP_ARGS[@]}" "${OUT}")"
STATUS=$?
set -e
case "${STATUS}" in
    0)
        echo "[package] build paths found inside the bundle:" >&2
        echo "${LEAKS}" >&2
        echo "[package] if it is the binary, rebuild it with" >&2
        echo "[package]   CARGO_ENCODED_RUSTFLAGS=\"\$(bash scripts/release_rustflags.sh)\" cargo build --release --locked" >&2
        exit 1
        ;;
    1) ;;
    *)
        echo "[package] leak check failed (grep exit ${STATUS})" >&2
        exit 1
        ;;
esac
echo "[package] ok: ${OUT}"
