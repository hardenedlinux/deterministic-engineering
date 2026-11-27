#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Unified Gerbil/Yuanxu Scheme test & script runner (bash 3.2+ & Linux/macOS compatible).
# Auto-discovers host Rust/CBMC/C/C++ toolchains and supports isolated per-suite execution
# with zero hardcoded suite names.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

if [[ -x "$HOME/.cargo/bin/rustup" ]]; then
  export RESOURCE_CARGO="${RESOURCE_CARGO:-$("$HOME/.cargo/bin/rustup" which cargo)}"
  export RESOURCE_RUSTC="${RESOURCE_RUSTC:-$("$HOME/.cargo/bin/rustup" which rustc)}"
fi

# Auto-populate SOURCE_CONTRACT_* tool paths when available on PATH.
auto_export_tool() {
  local var_name="$1"
  shift
  if [[ -n "${!var_name:-}" ]]; then
    return 0
  fi
  local bin=""
  for candidate in "$@"; do
    bin="$(command -v "$candidate" 2>/dev/null || true)"
    if [[ -n "$bin" ]]; then
      export "${var_name}=$(realpath "$bin")"
      return 0
    fi
  done
}

auto_export_tool SOURCE_CONTRACT_CBMC cbmc
auto_export_tool SOURCE_CONTRACT_GOTO_CC goto-cc
auto_export_tool SOURCE_CONTRACT_GOTO_INSTRUMENT goto-instrument
auto_export_tool SOURCE_CONTRACT_CC clang cc gcc
auto_export_tool SOURCE_CONTRACT_CXX clang++ c++ g++

export GAMBOPT="${GAMBOPT:-max-heap=2G,debug=q}"

run_with_darwin_env() {
  local gerbil_exec=""
  gerbil_exec="$(command -v gerbil 2>/dev/null || true)"
  if [[ "$(uname -s)" == "Darwin" && -n "$gerbil_exec" ]] && realpath "$gerbil_exec" | grep -Fq '/opt/homebrew/Cellar/'; then
    local ossl="${OPENSSL_PREFIX:-}"
    if [[ -z "$ossl" ]] && command -v brew >/dev/null 2>&1; then
      ossl="$(brew --prefix openssl@3 2>/dev/null || true)"
    fi
    env -u SDKROOT -u DEVELOPER_DIR -u CPATH -u LIBRARY_PATH -u C_INCLUDE_PATH \
        -u CPLUS_INCLUDE_PATH -u MACOSX_DEPLOYMENT_TARGET -u DYLD_LIBRARY_PATH \
        -u DYLD_FALLBACK_LIBRARY_PATH \
        COMPILER_PATH=/usr/bin \
        CPATH="${ossl}/include" \
        LIBRARY_PATH="${ossl}/lib" \
        PKG_CONFIG_PATH="${ossl}/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}" \
        "$@"
  else
    "$@"
  fi
}

exec_gxtest_file() {
  local path="$1"
  local pattern="${2:-.*}"
  local timeout_s="${3:-120s}"

  test -f "$path"
  mkdir -p .data/test-logs
  local log
  log="$(mktemp .data/test-logs/test-XXXXXX)"

  run_with_darwin_env timeout --foreground --signal=TERM --kill-after=5s "$timeout_s" \
    gerbil -:max-heap=2G,debug=q env gxtest -v 5 -r "$pattern" "$path" 2>&1 | tee "$log"

  if rg -q 'ERROR (MODULE|CHECK|CASE|HARNESS)|Heap overflow|Stack overflow' "$log"; then
    exit 1
  fi
  rg -F -x "MODULE-OK $path" "$log" >/dev/null
  rg -F 'HARNESS-OK' "$log" >/dev/null
  rg '^SUITE-OK ' "$log" >/dev/null
  rg '^CASE-OK ' "$log" >/dev/null
  rg -x 'OK' "$log" >/dev/null
}

exec_gxi_script() {
  local timeout_s="$1"
  local script="$2"
  shift 2
  mkdir -p .data/test-logs
  local log
  log="$(mktemp .data/test-logs/script-XXXXXX)"
  if [[ "$timeout_s" == "none" ]]; then
    run_with_darwin_env gerbil -:max-heap=2G,debug=q env gxi -:max-heap=2G,debug=q "$script" "$@"
  else
    run_with_darwin_env timeout --foreground --signal=TERM --kill-after=5s "$timeout_s" \
      gerbil -:max-heap=2G,debug=q env gxi -:max-heap=2G,debug=q "$script" "$@" 2>&1 | tee "$log"
  fi
}

cmd="${1:-}"
shift || true

case "$cmd" in
  file)
    exec_gxtest_file "${1:?missing test path}" "${2:-.*}" "${3:-120s}"
    ;;
  suites)
    # Dynamically extract every `(def <suite-id> ... (test-suite ...))` exported by <path>
    # and run each suite in an isolated bounded-heap process (zero hardcoded suite lists).
    target_path="${1:?missing test path}"
    timeout_s="${2:-120s}"
    test -f "$target_path"
    found=0
    while IFS= read -r suite_name; do
      [[ -z "$suite_name" ]] && continue
      found=1
      echo "=== [gxtest-suite] $target_path :: ^${suite_name}$ ==="
      exec_gxtest_file "$target_path" "^${suite_name}$" "$timeout_s"
    done < <(awk '
      /^\(def [A-Za-z0-9_.-]+/ {
        candidate = $2
        sub(/\).*/, "", candidate)
        if ($0 ~ /\(test-suite/) { print candidate; candidate = "" }
        next
      }
      candidate != "" && /\(test-suite/ { print candidate; candidate = ""; next }
      /^\(/ { candidate = "" }
    ' "$target_path")
    if [[ "$found" -eq 0 ]]; then
      exec_gxtest_file "$target_path" ".*" "$timeout_s"
    fi
    ;;
  dir)
    target_dir="${1:?missing directory}"
    timeout_s="${2:-120s}"
    name_glob="${3:-*-test.ss}"
    found=0
    while IFS= read -r f; do
      [[ -z "$f" ]] && continue
      found=1
      echo "=== [gxtest] $f ==="
      exec_gxtest_file "$f" ".*" "$timeout_s"
    done < <(find "$target_dir" -type f -name "$name_glob" | LC_ALL=C sort)
    if [[ "$found" -eq 0 ]]; then
      echo "ERROR: no Scheme test files matching '$name_glob' under '$target_dir'" >&2
      exit 1
    fi
    ;;
  formation)
    exec_gxi_script 120s projects/library-formation/test.ss "${1:?missing path}" "${2:?missing cases}"
    ;;
  script)
    timeout_s="${1:?missing timeout}"
    script="${2:?missing script}"
    shift 2
    exec_gxi_script "$timeout_s" "$script" "$@"
    ;;
  *)
    echo "Usage: $0 {file <path> [pattern] [timeout]|suites <path> [timeout]|dir <dir> [timeout] [glob]|formation <path> <cases>|script <timeout|none> <script> [args...]}" >&2
    exit 2
    ;;
esac
