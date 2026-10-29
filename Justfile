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
gerbil_darwin_env := if os() == "macos" { if gerbil_homebrew_runtime == "true" { "env -u SDKROOT -u DEVELOPER_DIR -u CPATH -u LIBRARY_PATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u MACOSX_DEPLOYMENT_TARGET -u DYLD_LIBRARY_PATH -u DYLD_FALLBACK_LIBRARY_PATH COMPILER_PATH=/usr/bin CPATH='" + darwin_openssl_prefix + "/include' LIBRARY_PATH='" + darwin_openssl_prefix + "/lib' PKG_CONFIG_PATH='" + darwin_openssl_prefix + "/lib/pkgconfig'" } else { "env" } } else { "env" }

# Native installation spans several package builds. Keep the original deadline
# at each package entry; a serial dependency closure is not one package build.
deps:
    timeout --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q deps --install


# The product owns the v0.19 tagged-update adapter over public gxpkg APIs.
# Run after initial installation; no local updater or manifest writer.
deps-update:
    timeout --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxi .gerbil/pkg/github.com/tao3k/agentic-ai-lab/packages/automation/native-dependencies.ss

# Use the ordinary untagged native build with the same host/compiler envelope.
build-dependency package:
    timeout --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxpkg build "{{ package }}"

build:
    timeout --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q build

test-file path pattern=".*":
    #!/usr/bin/env bash
    set -euo pipefail
    test -f "{{path}}"
    if test -x "$HOME/.cargo/bin/rustup"; then
      export RESOURCE_CARGO="${RESOURCE_CARGO:-$("$HOME/.cargo/bin/rustup" which cargo)}"
      export RESOURCE_RUSTC="${RESOURCE_RUSTC:-$("$HOME/.cargo/bin/rustup" which rustc)}"
    fi
    mkdir -p .data/test-logs
    log="$(mktemp .data/test-logs/test-XXXXXX)"
    timeout --signal=TERM --kill-after=5s 120s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxtest -:max-heap=2G,debug=q -v 5 -r "{{pattern}}" "{{path}}" 2>&1 | tee "$log"
    if rg 'ERROR (MODULE|CHECK|CASE|HARNESS)|Heap overflow|Stack overflow' "$log"; then exit 1; fi
    rg -F -x 'MODULE-OK {{path}}' "$log" >/dev/null
    rg -F 'HARNESS-OK' "$log" >/dev/null
    rg '^SUITE-OK ' "$log" >/dev/null
    rg '^CASE-OK ' "$log" >/dev/null
    rg -x 'OK' "$log" >/dev/null

# Serial execution preserves bounded native test ownership.
test:
    just test-file t/library-relation-types-test.ss
    just test-file t/resource-evidence-contract-test.ss
    just test-file t/resource-scenario-contract-test.ss
    just test-file t/library-owner-test.ss
    just test-file t/library-selection-test.ss
    just test-file t/native-context-test.ss
    just test-file t/module-design-test.ss
    just test-gateway
    just test-file t/dependency-compatibility-test.ss
    just test-file t/package-metadata-test.ss

# Each existing suite receives its own bounded native invocation.
test-gateway:
    #!/usr/bin/env bash
    set -euo pipefail
    for suite in initial method capacity cache-retry source boundaries counter; do
      just test-file t/gateway-library-test.ss "^gateway-$suite-test$"
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
    timeout --signal=TERM --kill-after=5s 600s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxi -:max-heap=2G,debug=q examples/resource-lifecycle-evidence.ss "{{output}}" "$cargo" "$rustc" "$quint" "$lean" 2>&1 | tee "$log"
    RESOURCE_REAL_REPORT="{{output}}/report.json" just test-file t/resource-lifecycle-test.ss

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
    timeout --signal=TERM --kill-after=5s 600s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxi -:max-heap=2G,debug=q examples/resource-integration-evidence.ss "{{output}}" "$cargo" "$rustc" "$quint" "$lean" "$(realpath "{{sysml}}")"
    d2 --layout elk --theme 0 --pad 24 "{{output}}/evidence.d2" "{{output}}/evidence.svg"

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
      "${power_guard[@]}" timeout --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxtest -:max-heap=2G,debug=q -v 5 -r "^backpressure-review-$group-test$" t/backpressure-review-test.ss 2>&1 | tee "$log"
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
    timeout --signal=TERM --kill-after=5s 240s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxi -:max-heap=2G,debug=q examples/backpressure-reassessment-evidence.ss "{{output}}" "$cargo" "$rustc"

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
    "${power_guard[@]}" timeout --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxtest -:max-heap=2G,debug=q -v 5 t/backpressure-reassessment-test.ss 2>&1 | tee "$log"
    if rg 'ERROR (MODULE|CHECK|CASE|HARNESS)|Heap overflow|Stack overflow' "$log"; then exit 1; fi
    rg -F -x 'MODULE-OK t/backpressure-reassessment-test.ss' "$log" >/dev/null
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
      "${power_guard[@]}" timeout --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxtest -:max-heap=2G,debug=q -v 5 t/backpressure-cross-intake-test.ss 2>&1 | tee "$log"
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
      "${power_guard[@]}" timeout --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxtest -:max-heap=2G,debug=q -v 5 "$test_module" 2>&1 | tee "$log"
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
      "${power_guard[@]}" timeout --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxtest -:max-heap=2G,debug=q -v 5 "$test_module" 2>&1 | tee "$log"
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
      "${power_guard[@]}" timeout --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gxtest -:max-heap=2G,debug=q -v 5 "$test_module" 2>&1 | tee "$log"
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
      "${power_guard[@]}" timeout --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gxtest -:max-heap=2G,debug=q -v 5 "$test_module" 2>&1 | tee "$log"
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
    "${power_guard[@]}" timeout --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxtest -:max-heap=2G,debug=q -v 5 t/producer-source-custody-test.ss 2>&1 | tee "$log"
    if rg 'ERROR (MODULE|CHECK|CASE|HARNESS)|Heap overflow|Stack overflow' "$log"; then exit 1; fi
    rg -F -x 'MODULE-OK t/producer-source-custody-test.ss' "$log" >/dev/null
    rg '^HARNESS-OK ' "$log" >/dev/null
    rg '^SUITE-OK ' "$log" >/dev/null
    rg '^CASE-OK ' "$log" >/dev/null
    rg -x 'OK' "$log" >/dev/null

# Reuse Core's real compiler / TestingScript / Fixture / Ops path.
test-library-declarations:
    just formation-test-file t/library-declaration-test.ss 4
    just formation-test-file t/library-model-chain-test.ss 4

test-organization-declarations:
    just formation-test-file t/organization-library-test.ss 3
    just formation-test-file t/library-method-binding-test.ss 2

test-codex-source:
    just formation-test-file t/codex-source-test.ss 2

test-codex-capture:
    just formation-test-file t/codex-capture-test.ss 1

test-project-inputs:
    just formation-test-file t/project-inputs-test.ss 3

test-library-mapping fixture:
    LIBRARY_TRACE_FIXTURE="{{fixture}}" just formation-test-file t/library-mapping-test.ss 3

test-library-selection:
    just formation-test-file t/library-selection-test.ss 2

test-project-formation:
    just formation-test-file t/project-formation-test.ss 14

test-project-formation-entry:
    just formation-test-file t/project-formation-entry-test.ss 3

test-project-formation-build:
    just formation-test-file t/project-formation-build-test.ss 2

# Core owns source/compiler preparation, Fixture, Ops and result admission.
formation-test-file path cases:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p .data/test-logs
    log="$(mktemp .data/test-logs/formation-test-XXXXXX)"
    timeout --signal=TERM --kill-after=5s 120s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxi -:max-heap=2G,debug=q projects/library-formation/test.ss "{{path}}" "{{cases}}" 2>&1 | tee "$log"

# Fresh candidate/report only; publication remains a separate protected activity.
investigate-project-formation output:
    #!/usr/bin/env bash
    set -euo pipefail
    test ! -e "{{output}}"
    mkdir -p .data/test-logs
    log="$(mktemp .data/test-logs/project-formation-XXXXXX)"
    timeout --signal=TERM --kill-after=5s 120s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxi -:max-heap=2G,debug=q examples/library-formation.ss "{{output}}" 2>&1 | tee "$log"

# Raw facts remain an explicitly untrusted design investigation interface.
investigate-formation-consequences output:
    #!/usr/bin/env bash
    set -euo pipefail
    test ! -e "{{output}}"
    mkdir -p .data/test-logs
    log="$(mktemp .data/test-logs/formation-consequences-XXXXXX)"
    timeout --signal=TERM --kill-after=5s 120s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxi -:max-heap=2G,debug=q examples/library-formation-consequences.ss "{{output}}" 2>&1 | tee "$log"
