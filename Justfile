# SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
#
# SPDX-License-Identifier: LGPL-2.1-or-later

# Native package operations; every Scheme process is fenced before importing.
set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# The native SDK derives concurrency from this machine; preserve caller limits.
# max-heap is per Scheme process, not a whole-build memory/worker cap.
export GERBIL_BUILD_CORES := env_var_or_default("GERBIL_BUILD_CORES", `gxi -:max-heap=2G -e '(display (##core-count))'`)
# Native package scripts spawn Scheme children: carry the same heap fence to them.
# Nested Just/SDK calls must retain the same compiler input identity.
export GAMBOPT := if env_var_or_default("GAMBOPT", "") == "" { "max-heap=2G,debug=q" } else if env_var("GAMBOPT") =~ "(^|,)max-heap=2G,debug=q$" { env_var("GAMBOPT") } else { env_var("GAMBOPT") + ",max-heap=2G,debug=q" }

# Align with agentic-ai-lab's Homebrew/Darwin compiler policy; native Gerbil
# still owns package resolution, environment and build dispatch.
gerbil_homebrew_runtime := `gerbil_executable="$(command -v gerbil 2>/dev/null || true)"; if [ -n "$gerbil_executable" ] && realpath "$gerbil_executable" | grep -F '/opt/homebrew/Cellar/' >/dev/null; then printf true; else printf false; fi`
homebrew_openssl_prefix := `if command -v brew >/dev/null 2>&1; then brew --prefix openssl@3 2>/dev/null || true; fi`
darwin_openssl_prefix := env_var_or_default("OPENSSL_PREFIX", homebrew_openssl_prefix)
gerbil_darwin_env := if os() == "macos" { if gerbil_homebrew_runtime == "true" { "env -u SDKROOT -u DEVELOPER_DIR -u CPATH -u LIBRARY_PATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u MACOSX_DEPLOYMENT_TARGET -u DYLD_LIBRARY_PATH -u DYLD_FALLBACK_LIBRARY_PATH COMPILER_PATH=/usr/bin CPATH='" + darwin_openssl_prefix + "/include' LIBRARY_PATH='" + darwin_openssl_prefix + "/lib' PKG_CONFIG_PATH=\"" + darwin_openssl_prefix + "/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}\"" } else { "env" } } else { "env" }

# Native installation spans several package builds. Keep the original deadline
# at each package entry; a serial dependency closure is not one package build.
deps:
    timeout --foreground --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q deps --install


# Gerbil's public package API owns tagged updates; no Parent path or manifest writer.
deps-update:
    timeout --foreground --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxi -e '(import (only-in :gerbil/tools/gxpkg pkg-update pkg-install with-pkg-build-env)) (with-pkg-build-env (for-each (lambda (dependency) (pkg-update dependency) (pkg-install dependency)) (pgetq depend: (call-with-input-file "gerbil.pkg" read) (quote ()))))'

# Use the ordinary untagged native build with the same host/compiler envelope.
build-dependency package:
    timeout --foreground --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxpkg build "{{ package }}"

build:
    timeout --foreground --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q build

test-file path pattern=".*" timeout_s="120s":
    #!/usr/bin/env bash
    set -euo pipefail
    test -f "{{path}}"
    if test -x "$HOME/.cargo/bin/rustup"; then
      export RESOURCE_CARGO="${RESOURCE_CARGO:-$("$HOME/.cargo/bin/rustup" which cargo)}"
      export RESOURCE_RUSTC="${RESOURCE_RUSTC:-$("$HOME/.cargo/bin/rustup" which rustc)}"
    fi
    mkdir -p .data/test-logs
    log="$(mktemp .data/test-logs/test-XXXXXX)"
    # Establish the native package environment before gxtest initializes imports.
    timeout --foreground --signal=TERM --kill-after=5s {{timeout_s}} {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxtest -v 5 -r "{{pattern}}" "{{path}}" 2>&1 | tee "$log"
    if rg 'ERROR (MODULE|CHECK|CASE|HARNESS)|Heap overflow|Stack overflow' "$log"; then exit 1; fi
    rg -F -x 'MODULE-OK {{path}}' "$log" >/dev/null
    rg -F 'HARNESS-OK' "$log" >/dev/null
    rg '^SUITE-OK ' "$log" >/dev/null
    rg '^CASE-OK ' "$log" >/dev/null
    rg -x 'OK' "$log" >/dev/null

# Yuanxu Loader test layout gate: enforces t/yanxu/Library/<owner>/*-test.ss ownership.
test-de-layout:
    just test-file t/integration/module-publication/loader-ownership-test.ss

# Loader-owned Quint methods, profiles & domain model qualification suites.
test-quint-models:
    #!/usr/bin/env bash
    set -euo pipefail
    just test-file t/yanxu/Library/quint-methods/projection-contracts-test.ss
    just test-file t/yanxu/Library/quint-profiles/convergence-test.ss
    just test-file t/yanxu/Library/bounded-capacity/contract-test.ss
    just test-file t/yanxu/Library/resource-lifetime/contract-test.ss
    for f in t/yanxu/*/*/qualification-test.ss; do
      just test-file "$f"
    done

# Serial execution preserves bounded native test ownership.
test:
    just test-de-layout
    just test-file t/integration/runtime/user-configuration-test.ss
    just test-source-contracts
    just test-file t/integration/library/engineering-ownership-test.ss
    just test-file t/integration/formation/repository-input-schema-test.ss
    just test-file t/integration/library/relation-types-test.ss
    just test-file t/yanxu/Library/evidence/resource-contract-test.ss
    just test-file t/yanxu/Library/evidence/catalog-test.ss
    just test-file t/yanxu/Library/resource-lifecycle-profiles/scenario-contract-test.ss
    just test-file t/integration/library/owner-test.ss
    just test-file t/integration/library/selection-test.ss
    just test-file t/integration/runtime/native-context-test.ss
    just test-file t/integration/runtime/native-concurrency-test.ss
    just test-file t/integration/runtime/rust-project-native-test.ss
    just test-file t/integration/library/module-design-test.ss
    just test-gateway
    just test-file t/integration/runtime/dependency-compatibility-test.ss
    just test-file t/integration/runtime/package-metadata-test.ss

# Real language subjects, current native tool paths and existing test harness.
test-source-contracts pattern=".*" path="t/yanxu/Library/source-contracts/contracts-test.ss":
    #!/usr/bin/env bash
    set -euo pipefail
    export SOURCE_CONTRACT_CBMC="$(realpath "$(command -v cbmc)")"
    export SOURCE_CONTRACT_GOTO_CC="$(realpath "$(command -v goto-cc)")"
    export SOURCE_CONTRACT_GOTO_INSTRUMENT="$(realpath "$(command -v goto-instrument)")"
    export SOURCE_CONTRACT_CC="$(realpath "$(command -v clang)")"
    export SOURCE_CONTRACT_CXX="$(realpath "$(command -v clang++)")"
    just test-file "{{path}}" "{{pattern}}"

investigate-source-contracts output:
    #!/usr/bin/env bash
    set -euo pipefail
    timeout --foreground --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxi t/support/source-contract-evidence.ss "{{output}}" "$(realpath "$(command -v cbmc)")" "$(realpath "$(command -v goto-cc)")" "$(realpath "$(command -v goto-instrument)")" "$(realpath "$(command -v clang)")" "$(realpath "$(command -v clang++)")"

# Each existing suite receives its own bounded native invocation.
test-gateway:
    #!/usr/bin/env bash
    set -euo pipefail
    for suite in initial method capacity cache-retry source boundaries counter; do
      just test-file t/yanxu/Library/gateway-profiles/gateway-library-test.ss "^gateway-$suite-test$"
    done

# Actual tools and issued results; output must be a fresh directory.
investigate-resource output:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo="${RESOURCE_CARGO:-$("$HOME/.cargo/bin/rustup" which cargo)}"
    rustc="${RESOURCE_RUSTC:-$("$HOME/.cargo/bin/rustup" which rustc)}"
    quint="${RESOURCE_QUINT:-$(realpath "$(command -v quint)")}"
    lean="${RESOURCE_LEAN:-$(elan which lean)}"
    test ! -e "{{output}}"
    mkdir -p .data/test-logs
    log="$(mktemp .data/test-logs/investigation-XXXXXX)"
    timeout --foreground --signal=TERM --kill-after=5s 600s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxi -:max-heap=2G,debug=q t/support/resource-lifecycle-evidence.ss "{{output}}" "$cargo" "$rustc" "$quint" "$lean" 2>&1 | tee "$log"
    RESOURCE_REAL_REPORT="{{output}}/report.json" just test-file t/yanxu/Library/resource-lifecycle-profiles/lifecycle-test.ss

# Optional SysML/correspondence slice with the existing native result issuer.
investigate-resource-integration output sysml:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo="${RESOURCE_CARGO:-$("$HOME/.cargo/bin/rustup" which cargo)}"
    rustc="${RESOURCE_RUSTC:-$("$HOME/.cargo/bin/rustup" which rustc)}"
    quint="${RESOURCE_QUINT:-$(realpath "$(command -v quint)")}"
    lean="${RESOURCE_LEAN:-$(elan which lean)}"
    test ! -e "{{output}}"
    test -x "{{sysml}}"
    timeout --foreground --signal=TERM --kill-after=5s 600s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxi -:max-heap=2G,debug=q t/support/resource-integration-evidence.ss "{{output}}" "$cargo" "$rustc" "$quint" "$lean" "$(realpath "{{sysml}}")"
    # Rendering requires the TS FigureInput contract; raw D2-to-SVG is retired.

# Native SDLC consumer of the accepted owner slice. No changes to its captured roots.
test-backpressure-review:
    #!/usr/bin/env bash
    set -euo pipefail
    power_guard=()
    if command -v caffeinate >/dev/null 2>&1; then power_guard=(caffeinate -dimsu); fi
    mkdir -p .data/test-logs .data/test-runs
    : "${BACKPRESSURE_ACCEPTANCE:?Provide the actual acceptance artifact}"
    : "${BACKPRESSURE_REVIEW_SOURCES:?Provide the actual runtime source artifact}"
    for group in applicability reuse counter corruption; do
      echo "REVIEW-GROUP $group"
      log="$(mktemp .data/test-logs/aitia-backpressure-XXXXXX)"
      "${power_guard[@]}" timeout --foreground --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxtest -:max-heap=2G,debug=q -v 5 -r "^backpressure-review-$group-test$" t/backpressure-review-test.ss 2>&1 | tee "$log"
      if rg 'ERROR (MODULE|CHECK|CASE|HARNESS)|Heap overflow|Stack overflow' "$log"; then exit 1; fi
      rg -F -x 'MODULE-OK t/backpressure-review-test.ss' "$log" >/dev/null
      rg -F 'HARNESS-OK' "$log" >/dev/null
      rg '^SUITE-OK ' "$log" >/dev/null
      rg '^CASE-OK ' "$log" >/dev/null
      rg -x 'OK' "$log" >/dev/null
      [[ "$(rg -c '^CASE-OK ' "$log")" == 1 ]]
    done

investigate-backpressure-reassessment output:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p .data/test-logs .data/test-runs
    cargo="${RESOURCE_CARGO:-$("$HOME/.cargo/bin/rustup" which cargo)}"
    rustc="${RESOURCE_RUSTC:-$("$HOME/.cargo/bin/rustup" which rustc)}"
    timeout --foreground --signal=TERM --kill-after=5s 240s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxi -:max-heap=2G,debug=q t/support/backpressure-reassessment-evidence.ss "{{output}}" "$cargo" "$rustc"

test-backpressure-reassessment:
    #!/usr/bin/env bash
    set -euo pipefail
    power_guard=()
    if command -v caffeinate >/dev/null 2>&1; then power_guard=(caffeinate -dimsu); fi
    project_root="$PWD"
    mkdir -p .data/test-logs .data/test-runs
    : "${BACKPRESSURE_REASSESSMENT_RUNS:?Provide the actual reassessment runs artifact}"
    : "${BACKPRESSURE_REVIEW_SOURCES:?Provide the actual runtime source artifact}"
    if [[ -z "${BACKPRESSURE_REASSESSMENT_REVIEW_OUTPUT:-}" ]]; then
      review_parent="$(mktemp -d "$project_root/.data/test-runs/review-XXXXXX")"
      export BACKPRESSURE_REASSESSMENT_REVIEW_OUTPUT="$review_parent/results"
    fi
    : "${BACKPRESSURE_ACCEPTANCE:?Provide the actual acceptance artifact}"
    log="$(mktemp .data/test-logs/aitia-reassessment-XXXXXX)"
    "${power_guard[@]}" timeout --foreground --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxtest -:max-heap=2G,debug=q -v 5 t/integration/backpressure/reassessment-test.ss 2>&1 | tee "$log"
    if rg 'ERROR (MODULE|CHECK|CASE|HARNESS)|Heap overflow|Stack overflow' "$log"; then exit 1; fi
    rg -F -x 'MODULE-OK t/integration/backpressure/reassessment-test.ss' "$log" >/dev/null
    rg -F 'HARNESS-OK' "$log" >/dev/null
    rg '^SUITE-OK ' "$log" >/dev/null
    rg '^CASE-OK ' "$log" >/dev/null
    rg -x 'OK' "$log" >/dev/null

# Existing real Rust runs, native ASCENT union, native Aitia authority and real signatures.
test-backpressure-cross-intake:
    #!/usr/bin/env bash
    set -euo pipefail
    power_guard=()
    if command -v caffeinate >/dev/null 2>&1; then power_guard=(caffeinate -dimsu); fi
    project_root="$PWD"
    mkdir -p .data/test-logs .data/test-runs
    : "${BACKPRESSURE_ACCEPTANCE:?Provide the actual acceptance artifact}"
    : "${BACKPRESSURE_REASSESSMENT_RUNS:?Provide the actual reassessment runs artifact}"
    : "${BACKPRESSURE_REVIEW_SOURCES:?Provide the actual runtime source artifact}"
    export BACKPRESSURE_OPENSSL="${BACKPRESSURE_OPENSSL:-$(realpath "$(command -v openssl)")}"
    for group in preflight discovery rejection authority reuse; do
      export BACKPRESSURE_CROSS_GROUP="$group"
      output_parent="$(mktemp -d "$project_root/.data/test-runs/review-$group-XXXXXX")"
      export BACKPRESSURE_CROSS_OUTPUT="$output_parent/results"
      log="$(mktemp .data/test-logs/aitia-cross-intake-XXXXXX)"
      "${power_guard[@]}" timeout --foreground --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxtest -:max-heap=2G,debug=q -v 5 t/backpressure-cross-intake-test.ss 2>&1 | tee "$log"
      if rg 'ERROR (MODULE|CHECK|CASE|HARNESS)|Heap overflow|Stack overflow' "$log"; then exit 1; fi
      rg -F -x 'MODULE-OK t/backpressure-cross-intake-test.ss' "$log" >/dev/null
      rg -F 'HARNESS-OK' "$log" >/dev/null
      rg '^SUITE-OK ' "$log" >/dev/null
      rg '^CASE-OK ' "$log" >/dev/null
      rg -x 'OK' "$log" >/dev/null
    done

# Existing real Rust runs, native ASCENT union, native Aitia authority and real signatures.
test-backpressure-owner-handover:
    #!/usr/bin/env bash
    set -euo pipefail
    power_guard=()
    if command -v caffeinate >/dev/null 2>&1; then power_guard=(caffeinate -dimsu); fi
    project_root="$PWD"
    mkdir -p .data/test-logs .data/test-runs
    : "${BACKPRESSURE_ACCEPTANCE:?Provide the actual acceptance artifact}"
    : "${BACKPRESSURE_REASSESSMENT_RUNS:?Provide the actual reassessment runs artifact}"
    : "${BACKPRESSURE_REVIEW_SOURCES:?Provide the actual runtime source artifact}"
    test_module="t/backpressure-owner-handover-test.ss"
    export BACKPRESSURE_OPENSSL="${BACKPRESSURE_OPENSSL:-$(realpath "$(command -v openssl)")}"
    for group in ${BACKPRESSURE_HANDOVER_GROUPS:-transfer reuse}; do
      export BACKPRESSURE_HANDOVER_GROUP="$group"
      output_parent="$(mktemp -d "$project_root/.data/test-runs/review-$group-XXXXXX")"
      export BACKPRESSURE_CROSS_OUTPUT="$output_parent/results"
      log="$(mktemp .data/test-logs/aitia-owner-handover-XXXXXX)"
      "${power_guard[@]}" timeout --foreground --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxtest -:max-heap=2G,debug=q -v 5 "$test_module" 2>&1 | tee "$log"
      if rg 'ERROR (MODULE|CHECK|CASE|HARNESS)|Heap overflow|Stack overflow' "$log"; then exit 1; fi
      rg -F -x "MODULE-OK $test_module" "$log" >/dev/null
      rg -F 'HARNESS-OK' "$log" >/dev/null
      rg '^SUITE-OK ' "$log" >/dev/null
      rg '^CASE-OK ' "$log" >/dev/null
      rg -x 'OK' "$log" >/dev/null
    done

# Four naturally exiting native processes; all later receipts are newly issued.
test-backpressure-owner-recovery:
    #!/usr/bin/env bash
    set -euo pipefail
    power_guard=()
    if command -v caffeinate >/dev/null 2>&1; then power_guard=(caffeinate -dimsu); fi
    project_root="$PWD"
    mkdir -p .data/test-logs .data/test-runs
    : "${BACKPRESSURE_ACCEPTANCE:?Provide the actual acceptance artifact}"
    : "${BACKPRESSURE_REASSESSMENT_RUNS:?Provide the actual reassessment runs artifact}"
    : "${BACKPRESSURE_REVIEW_SOURCES:?Provide the actual runtime source artifact}"
    test_module="t/backpressure-owner-recovery-test.ss"
    export BACKPRESSURE_OPENSSL="${BACKPRESSURE_OPENSSL:-$(realpath "$(command -v openssl)")}"
    export BACKPRESSURE_RECOVERY_ROOT="$(mktemp -d "$project_root/.data/test-runs/restart-XXXXXX")"
    for phase in producer restart-one restart-two restart-three; do
      export BACKPRESSURE_RECOVERY_PHASE="$phase"
      if [[ "$phase" != producer ]]; then
        export BACKPRESSURE_RECOVERY_SELECTION_SHA="$(shasum -a 256 "$BACKPRESSURE_RECOVERY_ROOT/host-selection.json" | cut -d ' ' -f 1)"
      fi
      log="$(mktemp .data/test-logs/aitia-owner-recovery-XXXXXX)"
      "${power_guard[@]}" timeout --foreground --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxtest -:max-heap=2G,debug=q -v 5 "$test_module" 2>&1 | tee "$log"
      if rg 'ERROR (MODULE|CHECK|CASE|HARNESS)|Heap overflow|Stack overflow' "$log"; then exit 1; fi
      rg -F -x "MODULE-OK $test_module" "$log" >/dev/null
      rg -F 'HARNESS-OK' "$log" >/dev/null
      rg '^SUITE-OK ' "$log" >/dev/null
      rg '^CASE-OK ' "$log" >/dev/null
      rg -x 'OK' "$log" >/dev/null
    done

# Real SIGKILL boundaries are expected only after a recorded local boundary.
test-backpressure-durable-intake:
    #!/usr/bin/env bash
    set -euo pipefail
    power_guard=()
    if command -v caffeinate >/dev/null 2>&1; then power_guard=(caffeinate -dimsu); fi
    project_root="$PWD"
    # Preserve the SDK child's actual signal exit; gerbil env wraps it as 70.
    export GERBIL_PATH="${GERBIL_PATH:-$project_root/.gerbil}"
    mkdir -p .data/test-logs .data/test-runs
    : "${BACKPRESSURE_ACCEPTANCE:?Provide the actual acceptance artifact}"
    : "${BACKPRESSURE_REASSESSMENT_RUNS:?Provide the actual reassessment runs artifact}"
    : "${BACKPRESSURE_REVIEW_SOURCES:?Provide the actual runtime source artifact}"
    test_module="t/backpressure-owner-recovery-test.ss"
    export BACKPRESSURE_OPENSSL="${BACKPRESSURE_OPENSSL:-$(realpath "$(command -v openssl)")}"
    export BACKPRESSURE_RECOVERY_ROOT="$(mktemp -d "$project_root/.data/test-runs/intake-XXXXXX")"
    for phase in intake-producer intake-recover intake-partial intake-pending; do
      export BACKPRESSURE_RECOVERY_PHASE="$phase"
      if [[ "$phase" != intake-producer ]]; then
        export BACKPRESSURE_RECOVERY_SELECTION_SHA="$(shasum -a 256 "$BACKPRESSURE_RECOVERY_ROOT/host-selection.json" | cut -d ' ' -f 1)"
      fi
      log="$(mktemp .data/test-logs/aitia-durable-intake-XXXXXX)"
      set +e
      "${power_guard[@]}" timeout --foreground --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gxtest -:max-heap=2G,debug=q -v 5 "$test_module" 2>&1 | tee "$log"
      status=${PIPESTATUS[0]}
      set -e
      echo "PROCESS-EXIT $phase $status"
      if rg 'ERROR (MODULE|CHECK|CASE|HARNESS)|Heap overflow|Stack overflow' "$log"; then exit 1; fi
      if [[ "$phase" == intake-pending ]]; then
        [[ "$status" == 0 ]]
        rg -F -x "MODULE-OK $test_module" "$log" >/dev/null
        rg '^HARNESS-OK ' "$log" >/dev/null
        rg '^SUITE-OK ' "$log" >/dev/null
        rg '^CASE-OK ' "$log" >/dev/null
        rg -x 'OK' "$log" >/dev/null
      else
        [[ "$status" == 137 ]]
        rg '^EXPECTED-SIGKILL ' "$log" >/dev/null
        [[ -s "$BACKPRESSURE_RECOVERY_ROOT/$phase/interrupt.json" ]]
        echo "INTERRUPTION-OK $phase status=$status"
      fi
    done

test-backpressure-prefix-repair:
    #!/usr/bin/env bash
    set -euo pipefail
    power_guard=()
    if command -v caffeinate >/dev/null 2>&1; then power_guard=(caffeinate -dimsu); fi
    project_root="$PWD"
    # Preserve the SDK child's actual signal exit; gerbil env wraps it as 70.
    export GERBIL_PATH="${GERBIL_PATH:-$project_root/.gerbil}"
    mkdir -p .data/test-logs .data/test-runs
    : "${BACKPRESSURE_ACCEPTANCE:?Provide the actual acceptance artifact}"
    : "${BACKPRESSURE_REASSESSMENT_RUNS:?Provide the actual reassessment runs artifact}"
    : "${BACKPRESSURE_REVIEW_SOURCES:?Provide the actual runtime source artifact}"
    test_module="t/backpressure-owner-recovery-test.ss"
    export BACKPRESSURE_OPENSSL="${BACKPRESSURE_OPENSSL:-$(realpath "$(command -v openssl)")}"
    export BACKPRESSURE_RECOVERY_ROOT="$(mktemp -d "$project_root/.data/test-runs/replay-XXXXXX")"
    for phase in intake-producer intake-recover intake-partial repair-checks repair-replay; do
      export BACKPRESSURE_RECOVERY_PHASE="$phase"
      if [[ "$phase" != intake-producer ]]; then
        export BACKPRESSURE_RECOVERY_SELECTION_SHA="$(shasum -a 256 "$BACKPRESSURE_RECOVERY_ROOT/host-selection.json" | cut -d ' ' -f 1)"
      fi
      log="$(mktemp .data/test-logs/aitia-durable-replay-XXXXXX)"
      set +e
      "${power_guard[@]}" timeout --foreground --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gxtest -:max-heap=2G,debug=q -v 5 "$test_module" 2>&1 | tee "$log"
      status=${PIPESTATUS[0]}
      set -e
      echo "PROCESS-EXIT $phase $status"
      if rg 'ERROR (MODULE|CHECK|CASE|HARNESS)|Heap overflow|Stack overflow' "$log"; then exit 1; fi
      if [[ "$phase" == repair-* ]]; then
        [[ "$status" == 0 ]]
        rg -F -x "MODULE-OK $test_module" "$log" >/dev/null
        rg '^HARNESS-OK ' "$log" >/dev/null
        rg '^SUITE-OK ' "$log" >/dev/null
        rg '^CASE-OK ' "$log" >/dev/null
        rg -x 'OK' "$log" >/dev/null
      else
        [[ "$status" == 137 ]]
        rg '^EXPECTED-SIGKILL ' "$log" >/dev/null
        [[ -s "$BACKPRESSURE_RECOVERY_ROOT/$phase/interrupt.json" ]]
        echo "INTERRUPTION-OK $phase status=$status"
      fi
    done

# Real archived producer bytes; all native authority is newly issued.
test-producer-source-custody:
    #!/usr/bin/env bash
    set -euo pipefail
    power_guard=()
    if command -v caffeinate >/dev/null 2>&1; then power_guard=(caffeinate -dimsu); fi
    project_root="$PWD"
    mkdir -p .data/test-logs .data/test-runs
    : "${BACKPRESSURE_ACCEPTANCE:?Provide the actual acceptance artifact}"
    export BACKPRESSURE_CUSTODY_OUTPUT="$(mktemp -d "$project_root/.data/test-runs/custody-XXXXXX")/results"
    log="$(mktemp "$project_root/.data/test-logs/custody-XXXXXX")"
    "${power_guard[@]}" timeout --foreground --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxtest -:max-heap=2G,debug=q -v 5 t/integration/backpressure/producer-source-custody-test.ss 2>&1 | tee "$log"
    if rg 'ERROR (MODULE|CHECK|CASE|HARNESS)|Heap overflow|Stack overflow' "$log"; then exit 1; fi
    rg -F -x 'MODULE-OK t/integration/backpressure/producer-source-custody-test.ss' "$log" >/dev/null
    rg '^HARNESS-OK ' "$log" >/dev/null
    rg '^SUITE-OK ' "$log" >/dev/null
    rg '^CASE-OK ' "$log" >/dev/null
    rg -x 'OK' "$log" >/dev/null

# Reuse Core's real compiler / TestingScript / Fixture / Ops path.
test-library-declarations:
    just formation-test-file t/yanxu/Library/backpressure-memory/declaration-test.ss 4
    just formation-test-file t/integration/library/model-chain-test.ss 4

test-organization-declarations:
    just formation-test-file t/yanxu/Library/project-organization/organization-library-test.ss 3
    just formation-test-file t/integration/library/method-binding-test.ss 2

test-codex-source:
    just formation-test-file t/codex-source-test.ss 2

test-codex-capture:
    just formation-test-file t/codex-capture-test.ss 1

test-project-inputs:
    just formation-test-file t/integration/formation/project-inputs-test.ss 3

test-library-mapping fixture:
    LIBRARY_TRACE_FIXTURE="{{fixture}}" just formation-test-file t/integration/library/mapping-test.ss 3

test-library-selection:
    just formation-test-file t/integration/library/selection-test.ss 2

test-project-formation:
    just formation-test-file t/yanxu/Library/library-formation-profiles/project-formation-test.ss 14

test-project-formation-entry:
    just formation-test-file t/integration/formation/project-formation-entry-test.ss 3

test-project-formation-build:
    just formation-test-file t/integration/formation/project-formation-build-test.ss 2

# Core owns source/compiler preparation, Fixture, Ops and result admission.
formation-test-file path cases:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p .data/test-logs
    log="$(mktemp .data/test-logs/formation-test-XXXXXX)"
    timeout --foreground --signal=TERM --kill-after=5s 120s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxi -:max-heap=2G,debug=q projects/library-formation/test.ss "{{path}}" "{{cases}}" 2>&1 | tee "$log"

# Fresh candidate/report only; publication remains a separate protected activity.
investigate-project-formation output:
    #!/usr/bin/env bash
    set -euo pipefail
    test ! -e "{{output}}"
    mkdir -p .data/test-logs
    log="$(mktemp .data/test-logs/project-formation-XXXXXX)"
    timeout --foreground --signal=TERM --kill-after=5s 120s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxi -:max-heap=2G,debug=q t/support/library-formation.ss "{{output}}" 2>&1 | tee "$log"

# Raw facts remain an explicitly untrusted design investigation interface.
investigate-formation-consequences output:
    #!/usr/bin/env bash
    set -euo pipefail
    test ! -e "{{output}}"
    mkdir -p .data/test-logs
    log="$(mktemp .data/test-logs/formation-consequences-XXXXXX)"
    timeout --foreground --signal=TERM --kill-after=5s 120s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxi -:max-heap=2G,debug=q t/support/library-formation-consequences.ss "{{output}}" 2>&1 | tee "$log"

# Unified engineering entrypoint for Quint packages (typecheck, unit/conformance tests, 37-model fleet plans & 35-model 100% MBT action-coverage gate).
check-quint:
    bun run check:quint

# Concurrent 37-model Quint plan fleet (typecheck + deterministic traces, pure TS).
fleet-quint:
    bun run fleet:quint

# Concurrent 40-model Quint MBT dead-action & coverage regression gate (100% action coverage).
mbt-quint:
    bun run mbt:quint

# Audit AI Agent patch/PR diffs (or explicit paths) for G2 defensive hallucinations across TS/C/C++/Rust/Scheme.
audit-agent-patch *args:
    bun languages-engineering/ts/defense/agent-audit/agent-defense-audit.ts {{ if args == "" { "--diff" } else { args } }}

# Unified D1-D4 + E2-E3 defensive-engineering verification gate (TS/C/C++/Rust contrasts, CBMC proof, MBT SUT refinement, 24-case 5-language Agent AST benchmark, Gerbil F1-F4/G1-G4/OR01-OR07).
check-defense:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p .data/test-runs/check-defense
    bun test languages-engineering/ts/defense/boundary-contrast/contrast.test.ts languages-engineering/ts/defense/boundary-contrast/mbt-replay.test.ts languages-engineering/ts/defense/agent-audit/agent-benchmark.test.ts languages-engineering/ts/defense/agent-audit/agent-defense-audit.test.ts languages-engineering/ts/defense/agent-audit/governance-harness.test.ts languages-engineering/ts/defense/agent-audit/durable-merkle-store.test.ts languages-engineering/ts/defense/agent-audit/durable-ai-context.test.ts languages-engineering/ts/defense/agent-audit/durable-business-orchestrator.test.ts languages-engineering/ts/defense/agent-audit/durable-hitl-approval.test.ts languages-engineering/ts/defense/agent-audit/capability-attenuation.test.ts languages-engineering/ts/defense/agent-audit/symbol-ssi-arbitrator.test.ts languages-engineering/ts/defense/agent-audit/durable-governance-pipeline.test.ts languages-engineering/ts/defense/agent-audit/durable-saga-budget.test.ts languages-engineering/ts/defense/agent-audit/difc-exfiltration-fence.test.ts languages-engineering/ts/defense/agent-audit/durable-memory-tms.test.ts languages-engineering/ts/defense/agent-audit/transparency-log-equivocation.test.ts
    clang -Wall -Wextra -Werror languages-engineering/c/defense/silent-fallback-contrast/bad_defensive.c languages-engineering/c/defense/silent-fallback-contrast/deterministic_boundary.c languages-engineering/c/defense/silent-fallback-contrast/contrast_test.c -o .data/test-runs/check-defense/c_contrast
    .data/test-runs/check-defense/c_contrast
    cbmc languages-engineering/c/defense/silent-fallback-contrast/deterministic_boundary.c languages-engineering/c/defense/silent-fallback-contrast/proof.c --bounds-check --pointer-check --unsigned-overflow-check
    clang++ -std=c++20 -Wall -Wextra -Werror languages-engineering/cpp/defense/raii-fallback-contrast/contrast_test.cpp -o .data/test-runs/check-defense/cpp_contrast
    .data/test-runs/check-defense/cpp_contrast
    "$("$HOME/.cargo/bin/rustup" which rustc)" --test languages-engineering/rust/defense/ownership-boundary-contrast/contrast.rs -o .data/test-runs/check-defense/rust_contrast
    .data/test-runs/check-defense/rust_contrast
    just test-file t/yanxu/Library/quint-methods/projection-contracts-test.ss
    just test-file t/yanxu/Library/defensive-boundaries/catalog-contract-test.ss
    just test-file t/yanxu/Library/defensive-governance/governance-ascent-test.ss
    just test-file t/yanxu/Library/defensive-governance/agent-benchmark-test.ss
    just test-file t/yanxu/Library/defense-profiles/convergence-test.ss
    just test-file t/yanxu/Library/project-organization/repository-organization-test.ss
    for f in t/yanxu/Quint.Engineering.Defense/*/qualification-test.ss; do
      just test-file "$f"
    done

# M5 multi-method verification gate (SysML v2 -> Zero-Glue Fun-Flow DAG Compiler -> Quint + LeanPoo 5-Core + Clippy + CBMC + Native Oracles -> ASCENT MR01-MR06/ER01-ER04/IR01-IR06 + Ed25519 Signed Cache & 4-Subject Fleet).
check-multi-method:
    just test-file t/yanxu/Library/verification-flow/governance-and-sysml-linkage-test.ss
    just test-file t/yanxu/Library/verification-flow/sysml-compiler-and-lease-fencing-test.ss ".*" 240s
    just test-file t/yanxu/Library/verification-flow/signed-cache-and-toolchain-attestation-test.ss ".*" 240s
    just test-file t/yanxu/Library/verification-flow/parallel-frontier-execution-test.ss ".*" 240s
    just test-file t/yanxu/Library/verification-flow/end-to-end-ops-runner-test.ss ".*" 240s
    just test-file t/yanxu/Library/verification-flow/incremental-cache-reuse-test.ss ".*" 240s
    just test-file t/yanxu/Library/verification-flow/multi-subject-backpressure-test.ss ".*" 240s
    just test-file t/yanxu/Library/verification-flow/multi-subject-fleet-and-pinned-attestation-test.ss ".*" 360s

# Run the M5 multi-method Fun-Flow Ops Runner (optional cache_dir & subject: process-tree-reclamation | backpressure-memory | lease-fencing-token | c-boundary-conservation) and write a fresh signed JSON evidence report.
investigate-multi-method output cache_dir="" subject="process-tree-reclamation":
    #!/usr/bin/env bash
    set -euo pipefail
    test ! -e "{{output}}"
    mkdir -p .data/test-logs
    log="$(mktemp .data/test-logs/multi-method-XXXXXX)"
    timeout --foreground --signal=TERM --kill-after=5s 300s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxi -:max-heap=2G,debug=q t/support/verification-flow-runner.ss "{{output}}" "{{cache_dir}}" "{{subject}}" 2>&1 | tee "$log"

# Run ALL SysML v2 subjects as one Ed25519-signed Merkle-bound Fleet against a shared cache.
fleet-multi-method output cache_dir="":
    #!/usr/bin/env bash
    set -euo pipefail
    test ! -e "{{output}}"
    mkdir -p .data/test-logs
    log="$(mktemp .data/test-logs/multi-method-fleet-XXXXXX)"
    timeout --foreground --signal=TERM --kill-after=5s 420s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxi -:max-heap=2G,debug=q t/support/verification-flow-runner.ss --fleet "{{output}}" "{{cache_dir}}" 2>&1 | tee "$log"

# Dry-run ASCENT IR01-IR06 change-impact & proof-reuse predictor across ALL SysML v2 subjects (<1s, zero engine spawns).
plan-multi-method-fleet cache_dir="":
    #!/usr/bin/env bash
    set -euo pipefail
    {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxi -:max-heap=2G,debug=q t/support/verification-flow-runner.ss --plan "{{cache_dir}}"
