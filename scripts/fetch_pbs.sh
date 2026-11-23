#!/usr/bin/env bash
# fetch_pbs.sh — download the pinned python-build-standalone runtime for one
# target, verify its SHA-256 and extract it.
#
# Usage: scripts/fetch_pbs.sh <rust-target-triple> <dest-dir>
#   e.g. scripts/fetch_pbs.sh x86_64-pc-windows-msvc dist/python
#
# The pin (release tag, Python version, one digest per target) lives in
# scripts/pbs.lock. Portable: bash 3.2+ (macOS), Linux, Git Bash on Windows.
#
# Invariants:
#   - HTTPS only; no sudo; writes only to vendor/cache/, a private temporary
#     directory and <dest-dir>.
#   - Nothing is extracted unless it matches its pinned SHA-256, and what is
#     extracted is the very copy that was hashed (a private temporary copy,
#     so nobody can swap the file between the check and tar).
#   - Downloads go to <archive>.part (resumed on the next run) and become
#     the cached <archive> only after verification. An archive that does
#     not match is moved aside (*.mismatch) and the script fails.
#
# PBS_LOCK=<file> overrides scripts/pbs.lock to test the mismatch path; it
# is refused in GitHub Actions.
#
# Exit codes:
#   0  success (<dest-dir> holds a working interpreter)
#   1  usage / file-system error, malformed lock, or unexpected archive layout
#   2  target not in pbs.lock
#   3  download failure
#   4  hash mismatch

set -euo pipefail
# The runtime ends up in the bundle: never group/other-writable, whatever
# the caller's umask (reli refuses a writable bundle on Unix).
umask 022

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <rust-target-triple> <dest-dir>" >&2
    exit 1
fi
TARGET_TRIPLE="$1"
DEST="$2"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CACHE="${ROOT}/vendor/cache"
LOCK="${ROOT}/scripts/pbs.lock"
if [[ -n "${PBS_LOCK:-}" ]]; then
    if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
        echo "[fetch_pbs] PBS_LOCK is not allowed in CI" >&2
        exit 1
    fi
    LOCK="${PBS_LOCK}"
fi

lock_value() { awk -v k="$1" '$1 == k { print $2 }' "${LOCK}"; }
TAG="$(lock_value tag)"
PY_VERSION="$(lock_value python)"
FLAVOR="$(lock_value flavor)"

# Every field ends up in a URL and a file name: accept only the expected
# shapes. A bash regex anchors at the ends of the whole value, so a key
# repeated in the lock (two lines from awk) is rejected too.
valid() {
    local re="^$2\$"
    [[ "$1" =~ ${re} ]]
}
if ! valid "${TAG}" '[0-9]{8}' || ! valid "${PY_VERSION}" '3\.12\.[0-9]+' ||
   ! valid "${FLAVOR}" '(install_only|install_only_stripped)'; then
    echo "[fetch_pbs] ${LOCK}: malformed or duplicated tag/python/flavor" >&2
    exit 1
fi
if ! valid "${TARGET_TRIPLE}" '[a-z0-9_]+(-[a-z0-9_]+){2,3}'; then
    echo "[fetch_pbs] malformed target triple: ${TARGET_TRIPLE}" >&2
    exit 1
fi
SHA256_EXPECTED="$(awk -v t="${TARGET_TRIPLE}" '$2 == t { print $1 }' "${LOCK}")"
if [[ -z "${SHA256_EXPECTED}" ]]; then
    echo "[fetch_pbs] target ${TARGET_TRIPLE} is not pinned in ${LOCK}" >&2
    exit 2
fi
if ! valid "${SHA256_EXPECTED}" '[0-9a-f]{64}'; then
    echo "[fetch_pbs] ${LOCK}: malformed or duplicated digest for ${TARGET_TRIPLE}" >&2
    exit 1
fi

ARCHIVE="cpython-${PY_VERSION}+${TAG}-${TARGET_TRIPLE}-${FLAVOR}.tar.gz"
URL="https://github.com/astral-sh/python-build-standalone/releases/download/${TAG}/${ARCHIVE}"
CACHED="${CACHE}/${ARCHIVE}"
PART="${CACHED}.part"

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{ print $1 }'
    else
        shasum -a 256 "$1" | awk '{ print $1 }'
    fi
}
matches() { [[ -f "$1" && "$(sha256_of "$1")" == "${SHA256_EXPECTED}" ]]; }
reject() {
    local actual
    actual="$(sha256_of "$1")"
    mv -f "$1" "${CACHED}.mismatch"
    echo "[fetch_pbs] SHA-256 mismatch for ${ARCHIVE}" >&2
    echo "  expected: ${SHA256_EXPECTED}" >&2
    echo "  actual:   ${actual}" >&2
    echo "[fetch_pbs] moved to ${CACHED}.mismatch; nothing extracted" >&2
}
download() {
    curl --fail --silent --show-error --location \
         --proto '=https' --proto-redir '=https' --tlsv1.2 \
         --retry 3 --retry-delay 2 "$@" --output "${PART}" "${URL}"
}

mkdir -p "${CACHE}"
echo "[fetch_pbs] ${TARGET_TRIPLE}: python ${PY_VERSION} (${TAG}, ${FLAVOR}) from ${LOCK}"

if matches "${CACHED}"; then
    echo "[fetch_pbs] cached archive matches its pin"
else
    if [[ -f "${CACHED}" ]]; then
        echo "[fetch_pbs] cached archive does not match its pin; downloading again" >&2
        reject "${CACHED}"
    fi
    if ! matches "${PART}"; then
        echo "[fetch_pbs] downloading ${URL}"
        # Resuming can fail or "succeed" on a corrupt .part (a longer one
        # gets 416, which curl takes as complete): then start over once.
        if ! download --continue-at - || ! matches "${PART}"; then
            echo "[fetch_pbs] resume did not produce the pinned archive; retrying from scratch" >&2
            rm -f "${PART}"
            if ! download; then
                echo "[fetch_pbs] download failed" >&2
                exit 3
            fi
        fi
    fi
    if ! matches "${PART}"; then
        reject "${PART}"
        exit 4
    fi
    mv -f "${PART}" "${CACHED}"
fi

# Hash and extract the same private copy (no TOCTOU on the shared cache).
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
chmod 700 "${WORK}"
cp "${CACHED}" "${WORK}/archive.tar.gz"
if ! matches "${WORK}/archive.tar.gz"; then
    echo "[fetch_pbs] the cached archive changed while it was being used" >&2
    exit 4
fi

rm -rf "${DEST}"
mkdir -p "${DEST}"
tar -xzf "${WORK}/archive.tar.gz" -C "${DEST}" --strip-components=1

case "${TARGET_TRIPLE}" in
    *-windows-*) PY="${DEST}/python.exe" ;;
    *)           PY="${DEST}/bin/python3" ;;
esac
if [[ ! -f "${PY}" ]]; then
    echo "[fetch_pbs] expected interpreter not found at ${PY} — archive layout changed?" >&2
    exit 1
fi
echo "[fetch_pbs] ok: ${PY}"
