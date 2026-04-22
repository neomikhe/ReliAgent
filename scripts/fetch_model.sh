#!/usr/bin/env bash
# fetch_model.sh — download a canonical model artifact listed in
# MODEL_SHA256.txt, verify its SHA-256, and drop it under vendor/models/.
#
# Usage:
#     scripts/fetch_model.sh                     # default quant (q4_k_m)
#     scripts/fetch_model.sh qwen2.5-7b-instruct-q5_k_m.gguf
#     scripts/fetch_model.sh --list              # show available artifacts
#
# Invariants:
#   - The Qwen licence URL from MODEL_SHA256.txt is printed and must be
#     explicitly accepted (set RELI_ACCEPT_MODEL_LICENSE=1 for CI).
#   - Every download is resumable via HTTP Range.
#   - SHA-256 mismatch is a hard stop. The partial file is kept on disk
#     for a retry to resume, but never extracted or used.
#
# Exit codes:
#   0  success
#   1  generic failure (argparse, fs)
#   2  unknown filename (not in MODEL_SHA256.txt)
#   3  download failure
#   4  hash mismatch
#   5  licence not accepted

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="${ROOT}/MODEL_SHA256.txt"
MODELS_DIR="${ROOT}/vendor/models"

# Mirror: the official HuggingFace endpoint. Override with RELI_MODEL_MIRROR
# for local / offline testing. Must be HTTPS.
MIRROR="${RELI_MODEL_MIRROR:-https://huggingface.co/Qwen/Qwen2.5-7B-Instruct-GGUF/resolve/main}"

usage() {
    cat <<'EOF'
Usage:
    scripts/fetch_model.sh              # default quant (q4_k_m)
    scripts/fetch_model.sh <filename>
    scripts/fetch_model.sh --list

Environment:
    RELI_MODEL_MIRROR          HTTPS base URL (default: HuggingFace Qwen GGUF)
    RELI_ACCEPT_MODEL_LICENSE  set to 1 to skip the interactive prompt
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage; exit 0
fi

# --- Parse MODEL_SHA256.txt ---------------------------------------------
if [[ ! -f "${MANIFEST}" ]]; then
    echo "[fetch_model] manifest not found: ${MANIFEST}" >&2
    exit 1
fi

declare -A SHA_BY_NAME
declare -A LIC_BY_NAME
while IFS= read -r line; do
    [[ -z "${line}" || "${line}" == \#* ]] && continue
    # Expect: <sha>  <name>  <bytes>  <license-url>
    read -r sha name _bytes lic <<<"${line}"
    [[ -z "${sha}" || -z "${name}" ]] && continue
    SHA_BY_NAME[${name}]="${sha}"
    LIC_BY_NAME[${name}]="${lic}"
done <"${MANIFEST}"

if [[ "${1:-}" == "--list" ]]; then
    for n in "${!SHA_BY_NAME[@]}"; do
        echo "${n}"
    done | sort
    exit 0
fi

NAME="${1:-qwen2.5-7b-instruct-q4_k_m.gguf}"

if [[ -z "${SHA_BY_NAME[$NAME]:-}" ]]; then
    echo "[fetch_model] unknown artifact: ${NAME}" >&2
    echo "[fetch_model] known artifacts (from MODEL_SHA256.txt):" >&2
    for n in "${!SHA_BY_NAME[@]}"; do echo "  ${n}"; done | sort >&2
    exit 2
fi

SHA_EXPECTED="${SHA_BY_NAME[$NAME]}"
LICENSE_URL="${LIC_BY_NAME[$NAME]}"

# --- Licence gate --------------------------------------------------------
echo "[fetch_model] artifact:  ${NAME}"
echo "[fetch_model] licence:   ${LICENSE_URL}"
echo "[fetch_model] Qwen2.5 is NOT Apache-2.0. You must accept Qwen's own terms."

if [[ "${RELI_ACCEPT_MODEL_LICENSE:-0}" != "1" ]]; then
    read -r -p "[fetch_model] type YES to accept the licence and continue: " REPLY
    if [[ "${REPLY}" != "YES" ]]; then
        echo "[fetch_model] licence not accepted; aborting." >&2
        exit 5
    fi
fi

# --- Download (resumable) ------------------------------------------------
mkdir -p "${MODELS_DIR}"
TARGET="${MODELS_DIR}/${NAME}"
URL="${MIRROR}/${NAME}"

echo "[fetch_model] url=${URL}"
if ! curl --fail --location --retry 3 --retry-delay 2 \
          --continue-at - --output "${TARGET}" "${URL}"; then
    echo "[fetch_model] download failed" >&2
    exit 3
fi

# --- Verify --------------------------------------------------------------
if [[ "${SHA_EXPECTED}" == REPLACE_WITH_SHA256* ]]; then
    echo "[fetch_model] WARN: placeholder SHA-256 for ${NAME}" >&2
    echo "[fetch_model] WARN: MODEL_SHA256.txt must be updated before release." >&2
    # Do not pretend the download is safe to use. Keep bytes on disk so the
    # user can inspect; exit with a hash-mismatch code.
    exit 4
fi

sha_actual="$(python3 -c \
    'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' \
    "${TARGET}")"

if [[ "${sha_actual}" != "${SHA_EXPECTED}" ]]; then
    echo "[fetch_model] SHA-256 mismatch" >&2
    echo "  expected: ${SHA_EXPECTED}" >&2
    echo "  actual:   ${sha_actual}" >&2
    echo "[fetch_model] keeping partial file at ${TARGET} for retry." >&2
    exit 4
fi

echo "[fetch_model] ok: ${TARGET}"
echo "[fetch_model] sha256 verified: ${sha_actual}"
