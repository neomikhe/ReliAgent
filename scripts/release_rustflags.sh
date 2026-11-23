#!/usr/bin/env bash
# release_rustflags.sh — print the value for CARGO_ENCODED_RUSTFLAGS that
# keeps local paths out of a release binary.
#
# rustc records source paths for panic messages and debug info. Without
# remapping, a binary built on a laptop carries e.g.
#   C:\Users\<name>\.cargo\registry\src\...
# Usage:
#   CARGO_ENCODED_RUSTFLAGS="$(bash scripts/release_rustflags.sh)" \
#       cargo build --release --locked
#
# Flags are separated by 0x1f (CARGO_ENCODED_RUSTFLAGS), so paths with
# spaces work. Portable: Linux, macOS (bash 3.2+), Git Bash on Windows.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CARGO_HOME_DIR="${CARGO_HOME:-${HOME}/.cargo}"
TARGET_DIR="${CARGO_TARGET_DIR:-${ROOT}/target}"

# rustc sees native paths: on Windows, C:\... rather than /c/...
native() {
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -w "$1"
    else
        printf '%s' "$1"
    fi
}

FLAGS=(
    "--remap-path-prefix=$(native "${CARGO_HOME_DIR}")=/cargo"
    "--remap-path-prefix=$(native "${TARGET_DIR}")=/target"
    "--remap-path-prefix=$(native "${ROOT}")=/reliagent"
)
(IFS=$'\x1f'; printf '%s' "${FLAGS[*]}")
