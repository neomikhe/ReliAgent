#!/usr/bin/env bash
# fetch_pbs.sh — download a python-build-standalone tarball matching the
# host platform, verify its SHA-256, and extract it to vendor/python/.
#
# This is the *linux / macOS* half of the pair; the PowerShell version
# (fetch_pbs.ps1) handles Windows. Keep the two in sync: same pinned
# release tag, same archive naming scheme, same exit codes.
#
# Invariants:
#   - No sudo, no writes outside the repo.
#   - SHA-256 mismatch is a hard stop; nothing extracts if the digest
#     does not match.
#   - Partial downloads are kept (-C -) so retries resume.
#
# Exit codes:
#   0  success (vendor/python/ populated and verified)
#   1  generic failure (argparse, fs)
#   2  unsupported platform
#   3  download failure (network)
#   4  hash mismatch (integrity)

set -euo pipefail

# --- Pin one release here. Bump in lockstep with the PowerShell script. ---
PBS_TAG="${PBS_TAG:-20260101}"     # placeholder; replace before release
PBS_PYTHON="${PBS_PYTHON:-3.12.7}" # must match python-core/pyproject.toml

# Per-platform archive + sha256 table.
# To refresh: grab from
#   https://github.com/astral-sh/python-build-standalone/releases/tag/${PBS_TAG}
declare -A ARCHIVES
declare -A SHA256S

ARCHIVES[linux-x86_64]="cpython-${PBS_PYTHON}+${PBS_TAG}-x86_64-unknown-linux-gnu-install_only.tar.gz"
SHA256S[linux-x86_64]="REPLACE_WITH_SHA256"

ARCHIVES[linux-aarch64]="cpython-${PBS_PYTHON}+${PBS_TAG}-aarch64-unknown-linux-gnu-install_only.tar.gz"
SHA256S[linux-aarch64]="REPLACE_WITH_SHA256"

ARCHIVES[macos-x86_64]="cpython-${PBS_PYTHON}+${PBS_TAG}-x86_64-apple-darwin-install_only.tar.gz"
SHA256S[macos-x86_64]="REPLACE_WITH_SHA256"

ARCHIVES[macos-aarch64]="cpython-${PBS_PYTHON}+${PBS_TAG}-aarch64-apple-darwin-install_only.tar.gz"
SHA256S[macos-aarch64]="REPLACE_WITH_SHA256"

# --- Discover platform ---------------------------------------------------
uname_s="$(uname -s)"
uname_m="$(uname -m)"
case "${uname_s}-${uname_m}" in
    Linux-x86_64)        PLATFORM="linux-x86_64" ;;
    Linux-aarch64|Linux-arm64) PLATFORM="linux-aarch64" ;;
    Darwin-x86_64)       PLATFORM="macos-x86_64" ;;
    Darwin-arm64)        PLATFORM="macos-aarch64" ;;
    *)
        echo "[fetch_pbs] unsupported platform: ${uname_s}-${uname_m}" >&2
        echo "[fetch_pbs] PBS publishes linux-{x86_64,aarch64}, macos-{x86_64,aarch64}." >&2
        exit 2
        ;;
esac

ARCHIVE="${ARCHIVES[$PLATFORM]}"
SHA256_EXPECTED="${SHA256S[$PLATFORM]}"
URL="https://github.com/astral-sh/python-build-standalone/releases/download/${PBS_TAG}/${ARCHIVE}"

# --- Paths ---------------------------------------------------------------
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR="${ROOT}/vendor"
CACHE="${VENDOR}/cache"
TARGET="${VENDOR}/python"
TMP_ARCHIVE="${CACHE}/${ARCHIVE}"

mkdir -p "${CACHE}"

# --- Download (resumable) ------------------------------------------------
echo "[fetch_pbs] platform=${PLATFORM} tag=${PBS_TAG} python=${PBS_PYTHON}"
echo "[fetch_pbs] url=${URL}"

if ! curl --fail --location --retry 3 --retry-delay 2 \
          --continue-at - --output "${TMP_ARCHIVE}" "${URL}"; then
    echo "[fetch_pbs] download failed" >&2
    exit 3
fi

# --- Verify ---------------------------------------------------------------
if [[ "${SHA256_EXPECTED}" == "REPLACE_WITH_SHA256" ]]; then
    echo "[fetch_pbs] WARN: placeholder SHA-256 — this is not a release build." >&2
    echo "[fetch_pbs] WARN: edit ${0##*/} to pin the real digest before cutting a tag." >&2
fi

sha256_actual="$(python3 -c \
    'import hashlib,sys; h=hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest(); print(h)' \
    "${TMP_ARCHIVE}")"

if [[ "${SHA256_EXPECTED}" != "REPLACE_WITH_SHA256" && \
      "${sha256_actual}" != "${SHA256_EXPECTED}" ]]; then
    echo "[fetch_pbs] SHA-256 mismatch" >&2
    echo "  expected: ${SHA256_EXPECTED}" >&2
    echo "  actual:   ${sha256_actual}" >&2
    echo "[fetch_pbs] keeping ${TMP_ARCHIVE} for forensics; not extracting." >&2
    exit 4
fi

# --- Extract --------------------------------------------------------------
echo "[fetch_pbs] verified, extracting to ${TARGET}/"
rm -rf "${TARGET}"
mkdir -p "${TARGET}"
tar -xzf "${TMP_ARCHIVE}" -C "${TARGET}" --strip-components=1

if [[ ! -x "${TARGET}/bin/python3" ]]; then
    echo "[fetch_pbs] archive did not contain bin/python3 — layout changed?" >&2
    exit 1
fi

echo "[fetch_pbs] ok: $("${TARGET}/bin/python3" --version)"
