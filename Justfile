# Native package operations; every Scheme process is fenced before importing.
set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

build:
    timeout --signal=TERM --kill-after=5s 180s gerbil -:max-heap=2G,debug=q build

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
    timeout --signal=TERM --kill-after=5s 120s gerbil -:max-heap=2G,debug=q env gxtest -:max-heap=2G,debug=q -v 5 -r "{{pattern}}" "{{path}}" 2>&1 | tee "$log"
    if rg 'ERROR (MODULE|CHECK|CASE|HARNESS)|Heap overflow|Stack overflow' "$log"; then exit 1; fi
    rg -F -x 'MODULE-OK {{path}}' "$log" >/dev/null
    rg -F 'HARNESS-OK' "$log" >/dev/null
    rg '^SUITE-OK ' "$log" >/dev/null
    rg '^CASE-OK ' "$log" >/dev/null
    rg -x 'OK' "$log" >/dev/null

# Serial execution preserves bounded native test ownership.
test:
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
    timeout --signal=TERM --kill-after=5s 600s gerbil -:max-heap=2G,debug=q env gxi -:max-heap=2G,debug=q examples/resource-lifecycle-evidence.ss "{{output}}" "$cargo" "$rustc" "$quint" "$lean" 2>&1 | tee "$log"
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
    launcher=(gerbil -:max-heap=2G,debug=q env gxi)
    if [[ -n "${RESOURCE_INTEGRATION_LOADPATH:-}" ]]; then
      export GERBIL_PATH="$PWD/.gerbil"
      export GERBIL_LOADPATH="$RESOURCE_INTEGRATION_LOADPATH"
      launcher=(gxi)
    fi
    timeout --signal=TERM --kill-after=5s 600s "${launcher[@]}" -:max-heap=2G,debug=q examples/resource-integration-evidence.ss "{{output}}" "$cargo" "$rustc" "$quint" "$lean" "$(realpath "{{sysml}}")"
    d2 --layout elk --theme 0 --pad 24 "{{output}}/evidence.d2" "{{output}}/evidence.svg"

# Native SDLC consumer of the accepted owner slice. No changes to its captured roots.
test-backpressure-review:
    #!/usr/bin/env bash
    set -euo pipefail
    power_guard=()
    if command -v caffeinate >/dev/null 2>&1; then power_guard=(caffeinate -dimsu); fi
    project_root="$PWD"
    flow_root="$(realpath .gerbil/pkg/github.com/tao3k/poo-flow)"
    export GERBIL_PATH="$project_root/.gerbil"
    export BACKPRESSURE_REVIEW_LIB="${BACKPRESSURE_REVIEW_LIB:-$project_root/.data/aitia-capacity-20261020/native-build-10/lib}"
    export GERBIL_LOADPATH="${BACKPRESSURE_REVIEW_LIB:+$BACKPRESSURE_REVIEW_LIB:}$project_root/.data/qualification-20261019:$flow_root/packages/lambda-aitia:$flow_root:$project_root/.gerbil/lib:$project_root"
    export BACKPRESSURE_ACCEPTANCE="${BACKPRESSURE_ACCEPTANCE:-$project_root/.data/qualification-20261019/acceptance.json}"
    export BACKPRESSURE_REVIEW_SOURCES="${BACKPRESSURE_REVIEW_SOURCES:-$project_root/.data/aitia-prefix-repair-20261020/qualification-21/runtime-sources.json}"
    mkdir -p .data/test-logs
    for group in applicability reuse counter corruption; do
      echo "REVIEW-GROUP $group"
      log="$(mktemp .data/test-logs/aitia-backpressure-XXXXXX)"
      "${power_guard[@]}" timeout --signal=TERM --kill-after=5s 180s gxtest -:max-heap=2G,debug=q -v 5 -r "^backpressure-review-$group-test$" t/backpressure-review-test.ss 2>&1 | tee "$log"
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
    project_root="$PWD"
    flow_root="$(realpath .gerbil/pkg/github.com/tao3k/poo-flow)"
    export GERBIL_PATH="$project_root/.gerbil"
    export GERBIL_LOADPATH="$project_root/.data/qualification-20261019:$flow_root/packages/lambda-aitia:$flow_root:$project_root/.gerbil/lib:$project_root"
    cargo="${RESOURCE_CARGO:-$("$HOME/.cargo/bin/rustup" which cargo)}"
    rustc="${RESOURCE_RUSTC:-$("$HOME/.cargo/bin/rustup" which rustc)}"
    timeout --signal=TERM --kill-after=5s 240s gxi -:max-heap=2G,debug=q examples/backpressure-reassessment-evidence.ss "{{output}}" "$cargo" "$rustc"

test-backpressure-reassessment:
    #!/usr/bin/env bash
    set -euo pipefail
    power_guard=()
    if command -v caffeinate >/dev/null 2>&1; then power_guard=(caffeinate -dimsu); fi
    project_root="$PWD"
    flow_root="$(realpath .gerbil/pkg/github.com/tao3k/poo-flow)"
    export GERBIL_PATH="$project_root/.gerbil"
    export BACKPRESSURE_REVIEW_LIB="${BACKPRESSURE_REVIEW_LIB:-$project_root/.data/aitia-capacity-20261020/native-build-10/lib}"
    export GERBIL_LOADPATH="${BACKPRESSURE_REVIEW_LIB:+$BACKPRESSURE_REVIEW_LIB:}$project_root/.data/qualification-20261019:$flow_root/packages/lambda-aitia:$flow_root:$project_root/.gerbil/lib:$project_root"
    export BACKPRESSURE_REASSESSMENT_RUNS="${BACKPRESSURE_REASSESSMENT_RUNS:-$project_root/.data/aitia-reassessment-20261019/native/runs.json}"
    export BACKPRESSURE_REVIEW_SOURCES="${BACKPRESSURE_REVIEW_SOURCES:-$project_root/.data/aitia-prefix-repair-20261020/qualification-21/runtime-sources.json}"
    if [[ -z "${BACKPRESSURE_REASSESSMENT_REVIEW_OUTPUT:-}" ]]; then
      review_parent="$(mktemp -d "$project_root/.data/aitia-reassessment-20261019/review-XXXXXX")"
      export BACKPRESSURE_REASSESSMENT_REVIEW_OUTPUT="$review_parent/results"
    fi
    export BACKPRESSURE_ACCEPTANCE="$project_root/.data/qualification-20261019/acceptance.json"
    mkdir -p .data/test-logs
    log="$(mktemp .data/test-logs/aitia-reassessment-XXXXXX)"
    "${power_guard[@]}" timeout --signal=TERM --kill-after=5s 180s gxtest -:max-heap=2G,debug=q -v 5 t/backpressure-reassessment-test.ss 2>&1 | tee "$log"
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
    flow_root="$(realpath .gerbil/pkg/github.com/tao3k/poo-flow)"
    export GERBIL_PATH="$project_root/.gerbil"
    export BACKPRESSURE_REVIEW_LIB="${BACKPRESSURE_REVIEW_LIB:-$project_root/.data/aitia-capacity-20261020/native-build-10/lib}"
    export GERBIL_LOADPATH="${BACKPRESSURE_REVIEW_LIB:+$BACKPRESSURE_REVIEW_LIB:}$project_root/.data/qualification-20261019:$flow_root/packages/lambda-aitia:$flow_root:$project_root/.gerbil/lib:$project_root"
    export BACKPRESSURE_ACCEPTANCE="$project_root/.data/qualification-20261019/acceptance.json"
    export BACKPRESSURE_REASSESSMENT_RUNS="$project_root/.data/aitia-reassessment-20261019/native/runs.json"
    export BACKPRESSURE_REVIEW_SOURCES="${BACKPRESSURE_REVIEW_SOURCES:-$project_root/.data/aitia-prefix-repair-20261020/qualification-21/runtime-sources.json}"
    export BACKPRESSURE_OPENSSL="${BACKPRESSURE_OPENSSL:-$(realpath "$(command -v openssl)")}"
    mkdir -p .data/test-logs
    for group in preflight discovery rejection authority reuse; do
      export BACKPRESSURE_CROSS_GROUP="$group"
      output_parent="$(mktemp -d "$project_root/.data/aitia-cross-intake-20261019/review-$group-XXXXXX")"
      export BACKPRESSURE_CROSS_OUTPUT="$output_parent/results"
      log="$(mktemp .data/test-logs/aitia-cross-intake-XXXXXX)"
      "${power_guard[@]}" timeout --signal=TERM --kill-after=5s 180s gxtest -:max-heap=2G,debug=q -v 5 t/backpressure-cross-intake-test.ss 2>&1 | tee "$log"
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
    flow_root="$(realpath .gerbil/pkg/github.com/tao3k/poo-flow)"
    export GERBIL_PATH="$project_root/.gerbil"
    export BACKPRESSURE_REVIEW_LIB="${BACKPRESSURE_REVIEW_LIB:-$project_root/.data/aitia-capacity-20261020/native-build-10/lib}"
    export GERBIL_LOADPATH="${BACKPRESSURE_REVIEW_LIB:+$BACKPRESSURE_REVIEW_LIB:}$project_root/.data/qualification-20261019:$flow_root/packages/lambda-aitia:$flow_root:$project_root/.gerbil/lib:$project_root"
    export BACKPRESSURE_ACCEPTANCE="$project_root/.data/qualification-20261019/acceptance.json"
    export BACKPRESSURE_REASSESSMENT_RUNS="$project_root/.data/aitia-reassessment-20261019/native/runs.json"
    export BACKPRESSURE_REVIEW_SOURCES="${BACKPRESSURE_REVIEW_SOURCES:-$project_root/.data/aitia-prefix-repair-20261020/qualification-21/runtime-sources.json}"
    test_module="t/backpressure-owner-handover-test.ss"
    if [[ -n "${BACKPRESSURE_NATIVE_TEST_LIB:-}" ]]; then
      test_module="$BACKPRESSURE_NATIVE_TEST_LIB/deterministic-engineering/t/backpressure-owner-handover-test.ssi"
      export GERBIL_LOADPATH="$BACKPRESSURE_NATIVE_TEST_LIB:$GERBIL_LOADPATH"
    fi
    export BACKPRESSURE_OPENSSL="${BACKPRESSURE_OPENSSL:-$(realpath "$(command -v openssl)")}"
    mkdir -p .data/test-logs
    for group in ${BACKPRESSURE_HANDOVER_GROUPS:-transfer reuse}; do
      export BACKPRESSURE_HANDOVER_GROUP="$group"
      output_parent="$(mktemp -d "$project_root/.data/aitia-owner-handover-20261019/review-$group-XXXXXX")"
      export BACKPRESSURE_CROSS_OUTPUT="$output_parent/results"
      log="$(mktemp .data/test-logs/aitia-owner-handover-XXXXXX)"
      "${power_guard[@]}" timeout --signal=TERM --kill-after=5s 180s gxtest -:max-heap=2G,debug=q -v 5 "$test_module" 2>&1 | tee "$log"
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
    flow_root="$(realpath .gerbil/pkg/github.com/tao3k/poo-flow)"
    export GERBIL_PATH="$project_root/.gerbil"
    export BACKPRESSURE_REVIEW_LIB="${BACKPRESSURE_REVIEW_LIB:-$project_root/.data/aitia-capacity-20261020/native-build-10/lib}"
    export GERBIL_LOADPATH="${BACKPRESSURE_REVIEW_LIB:+$BACKPRESSURE_REVIEW_LIB:}$project_root/.data/qualification-20261019:$flow_root/packages/lambda-aitia:$flow_root:$project_root/.gerbil/lib:$project_root"
    export BACKPRESSURE_ACCEPTANCE="$project_root/.data/qualification-20261019/acceptance.json"
    export BACKPRESSURE_REASSESSMENT_RUNS="$project_root/.data/aitia-reassessment-20261019/native/runs.json"
    export BACKPRESSURE_REVIEW_SOURCES="${BACKPRESSURE_REVIEW_SOURCES:-$project_root/.data/aitia-prefix-repair-20261020/qualification-21/runtime-sources.json}"
    test_module="t/backpressure-owner-recovery-test.ss"
    if [[ -n "${BACKPRESSURE_NATIVE_TEST_LIB:-}" ]]; then
      test_module="$BACKPRESSURE_NATIVE_TEST_LIB/deterministic-engineering/t/backpressure-owner-recovery-test.ssi"
      export GERBIL_LOADPATH="$BACKPRESSURE_NATIVE_TEST_LIB:$GERBIL_LOADPATH"
    fi
    export BACKPRESSURE_OPENSSL="${BACKPRESSURE_OPENSSL:-$(realpath "$(command -v openssl)")}"
    export BACKPRESSURE_RECOVERY_ROOT="$(mktemp -d "$project_root/.data/aitia-owner-recovery-20261019/restart-XXXXXX")"
    mkdir -p .data/test-logs
    for phase in producer restart-one restart-two restart-three; do
      export BACKPRESSURE_RECOVERY_PHASE="$phase"
      if [[ "$phase" != producer ]]; then
        export BACKPRESSURE_RECOVERY_SELECTION_SHA="$(shasum -a 256 "$BACKPRESSURE_RECOVERY_ROOT/host-selection.json" | cut -d ' ' -f 1)"
      fi
      log="$(mktemp .data/test-logs/aitia-owner-recovery-XXXXXX)"
      "${power_guard[@]}" timeout --signal=TERM --kill-after=5s 180s gxtest -:max-heap=2G,debug=q -v 5 "$test_module" 2>&1 | tee "$log"
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
    flow_root="$(realpath .gerbil/pkg/github.com/tao3k/poo-flow)"
    export GERBIL_PATH="$project_root/.gerbil"
    export BACKPRESSURE_REVIEW_LIB="${BACKPRESSURE_REVIEW_LIB:-$project_root/.data/aitia-capacity-20261020/native-build-10/lib}"
    export GERBIL_LOADPATH="${BACKPRESSURE_REVIEW_LIB:+$BACKPRESSURE_REVIEW_LIB:}$project_root/.data/qualification-20261019:$flow_root/packages/lambda-aitia:$flow_root:$project_root/.gerbil/lib:$project_root"
    export BACKPRESSURE_ACCEPTANCE="$project_root/.data/qualification-20261019/acceptance.json"
    export BACKPRESSURE_REASSESSMENT_RUNS="$project_root/.data/aitia-reassessment-20261019/native/runs.json"
    export BACKPRESSURE_REVIEW_SOURCES="${BACKPRESSURE_REVIEW_SOURCES:-$project_root/.data/aitia-prefix-repair-20261020/qualification-21/runtime-sources.json}"
    test_module="t/backpressure-owner-recovery-test.ss"
    if [[ -n "${BACKPRESSURE_NATIVE_TEST_LIB:-}" ]]; then
      test_module="$BACKPRESSURE_NATIVE_TEST_LIB/deterministic-engineering/t/backpressure-owner-recovery-test.ssi"
      export GERBIL_LOADPATH="$BACKPRESSURE_NATIVE_TEST_LIB:$GERBIL_LOADPATH"
    fi
    export BACKPRESSURE_OPENSSL="${BACKPRESSURE_OPENSSL:-$(realpath "$(command -v openssl)")}"
    export BACKPRESSURE_RECOVERY_ROOT="$(mktemp -d "$project_root/.data/aitia-durable-intake-20261019/intake-XXXXXX")"
    mkdir -p .data/test-logs
    for phase in intake-producer intake-recover intake-partial intake-pending; do
      export BACKPRESSURE_RECOVERY_PHASE="$phase"
      if [[ "$phase" != intake-producer ]]; then
        export BACKPRESSURE_RECOVERY_SELECTION_SHA="$(shasum -a 256 "$BACKPRESSURE_RECOVERY_ROOT/host-selection.json" | cut -d ' ' -f 1)"
      fi
      log="$(mktemp .data/test-logs/aitia-durable-intake-XXXXXX)"
      set +e
      "${power_guard[@]}" timeout --signal=TERM --kill-after=5s 180s gxtest -:max-heap=2G,debug=q -v 5 "$test_module" 2>&1 | tee "$log"
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
    flow_root="$(realpath .gerbil/pkg/github.com/tao3k/poo-flow)"
    export GERBIL_PATH="$project_root/.gerbil"
    export BACKPRESSURE_REVIEW_LIB="${BACKPRESSURE_REVIEW_LIB:-$project_root/.data/aitia-capacity-20261020/native-build-10/lib}"
    export GERBIL_LOADPATH="${BACKPRESSURE_REVIEW_LIB:+$BACKPRESSURE_REVIEW_LIB:}$project_root/.data/qualification-20261019:$flow_root/packages/lambda-aitia:$flow_root:$project_root/.gerbil/lib:$project_root"
    export BACKPRESSURE_ACCEPTANCE="$project_root/.data/qualification-20261019/acceptance.json"
    export BACKPRESSURE_REASSESSMENT_RUNS="$project_root/.data/aitia-reassessment-20261019/native/runs.json"
    export BACKPRESSURE_REVIEW_SOURCES="${BACKPRESSURE_REVIEW_SOURCES:-$project_root/.data/aitia-prefix-repair-20261020/qualification-21/runtime-sources.json}"
    test_module="t/backpressure-owner-recovery-test.ss"
    if [[ -n "${BACKPRESSURE_NATIVE_TEST_LIB:-}" ]]; then
      test_module="$BACKPRESSURE_NATIVE_TEST_LIB/deterministic-engineering/t/backpressure-owner-recovery-test.ssi"
      export GERBIL_LOADPATH="$BACKPRESSURE_NATIVE_TEST_LIB:$GERBIL_LOADPATH"
    fi
    export BACKPRESSURE_OPENSSL="${BACKPRESSURE_OPENSSL:-$(realpath "$(command -v openssl)")}"
    export BACKPRESSURE_RECOVERY_ROOT="$(mktemp -d "$project_root/.data/aitia-prefix-repair-20261020/replay-XXXXXX")"
    mkdir -p .data/test-logs
    for phase in intake-producer intake-recover intake-partial repair-checks repair-replay; do
      export BACKPRESSURE_RECOVERY_PHASE="$phase"
      if [[ "$phase" != intake-producer ]]; then
        export BACKPRESSURE_RECOVERY_SELECTION_SHA="$(shasum -a 256 "$BACKPRESSURE_RECOVERY_ROOT/host-selection.json" | cut -d ' ' -f 1)"
      fi
      log="$(mktemp .data/test-logs/aitia-durable-replay-XXXXXX)"
      set +e
      "${power_guard[@]}" timeout --signal=TERM --kill-after=5s 180s gxtest -:max-heap=2G,debug=q -v 5 "$test_module" 2>&1 | tee "$log"
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
    flow_root="$(realpath .gerbil/pkg/github.com/tao3k/poo-flow)"
    export GERBIL_PATH="$project_root/.gerbil"
    export GERBIL_LOADPATH="$BACKPRESSURE_REVIEW_LIB:$project_root/.data/qualification-20261019:$flow_root/packages/lambda-aitia:$flow_root:$project_root/.gerbil/lib:$project_root"
    export BACKPRESSURE_ACCEPTANCE="$project_root/.data/qualification-20261019/acceptance.json"
    export BACKPRESSURE_CUSTODY_OUTPUT="$(mktemp -d "$project_root/.data/aitia-capacity-20261020/custody-XXXXXX")/results"
    log="$(mktemp "$project_root/.data/test-logs/custody-XXXXXX")"
    "${power_guard[@]}" timeout --signal=TERM --kill-after=5s 180s gxtest -:max-heap=2G,debug=q -v 5 t/producer-source-custody-test.ss 2>&1 | tee "$log"
    if rg 'ERROR (MODULE|CHECK|CASE|HARNESS)|Heap overflow|Stack overflow' "$log"; then exit 1; fi
    rg -F -x 'MODULE-OK t/producer-source-custody-test.ss' "$log" >/dev/null
    rg '^HARNESS-OK ' "$log" >/dev/null
    rg '^SUITE-OK ' "$log" >/dev/null
    rg '^CASE-OK ' "$log" >/dev/null
    rg -x 'OK' "$log" >/dev/null

# Native pins remain in gerbil.pkg; patches are explicit reviewed development inputs.
formation-runtime:
    @python3 dev/formation-environment.py >/dev/null

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
    FORMATION_WITH_CONTEXT=1 just formation-test-file t/library-selection-test.ss 2

test-project-formation:
    just formation-test-file t/project-formation-test.ss 14

test-project-formation-entry:
    just formation-test-file t/project-formation-entry-test.ss 3

test-project-formation-build:
    just formation-test-file t/project-formation-build-test.ss 3

# Core owns source/compiler preparation, Fixture, Ops and result admission.
formation-test-file path cases:
    #!/usr/bin/env bash
    set -euo pipefail
    export FORMATION_WITH_CONTEXT="${FORMATION_WITH_CONTEXT:-1}"
    eval "$(python3 dev/formation-environment.py)"
    mkdir -p .data/test-logs
    log="$(mktemp .data/test-logs/formation-test-XXXXXX)"
    env -u SDKROOT timeout --signal=TERM --kill-after=5s 120s gxi -:max-heap=2G,debug=q dev/formation-test.ss "{{path}}" "{{cases}}" 2>&1 | tee "$log"

# Fresh candidate/report only; publication remains a separate protected activity.
investigate-project-formation output:
    #!/usr/bin/env bash
    set -euo pipefail
    test ! -e "{{output}}"
    export FORMATION_WITH_CONTEXT="${FORMATION_WITH_CONTEXT:-1}"
    eval "$(python3 dev/formation-environment.py)"
    mkdir -p .data/test-logs
    log="$(mktemp .data/test-logs/project-formation-XXXXXX)"
    env -u SDKROOT timeout --signal=TERM --kill-after=5s 120s gxi -:max-heap=2G,debug=q examples/library-formation.ss "{{output}}" 2>&1 | tee "$log"

# Complete dependency build, with separate artifacts from the source test lane.
build-formation-dependency:
    #!/usr/bin/env bash
    set -euo pipefail
    export FORMATION_COHORT="${FORMATION_COHORT:-$PWD/.data/formation-build}"
    export FORMATION_WITH_CONTEXT="${FORMATION_WITH_CONTEXT:-1}"
    eval "$(python3 dev/formation-environment.py)"
    export GERBIL_BUILD_CORES=4
    mkdir -p .data/test-logs
    log="$(mktemp "$PWD/.data/test-logs/formation-dependency-build-XXXXXX")"
    cd "${FORMATION_DEPENDENCIES:-$PWD/.data/formation-dependencies}/gerbil-poo"
    env -u SDKROOT timeout --verbose --signal=TERM --kill-after=5s 180s gxi -:max-heap=2G,debug=q build.ss library compile 2>&1 | tee "$log"

# Run dependency stages serially; each retains its own fixed complete-build cap.
build-formation-core:
    #!/usr/bin/env bash
    set -euo pipefail
    export FORMATION_COHORT="${FORMATION_COHORT:-$PWD/.data/formation-build}"
    export FORMATION_WITH_CONTEXT="${FORMATION_WITH_CONTEXT:-1}"
    eval "$(python3 dev/formation-environment.py)"
    export GERBIL_LOADPATH="$GERBIL_PATH/lib:$GERBIL_LOADPATH"
    export GERBIL_BUILD_CORES=4
    mkdir -p .data/test-logs
    log="$(mktemp "$PWD/.data/test-logs/formation-core-build-XXXXXX")"
    cd "${FORMATION_DEPENDENCIES:-$PWD/.data/formation-dependencies}/yuanxu"
    env -u SDKROOT timeout --verbose --signal=TERM --kill-after=5s 180s gxi -:max-heap=2G,debug=q build.ss compile 2>&1 | tee "$log"

# Tool choices are explicit arguments; no compiler or OpenSSL fallback is inferred.
build-formation-ascent compiler pkg_config_path tool_path:
    #!/usr/bin/env bash
    set -euo pipefail
    export FORMATION_TOOL_PATH="{{tool_path}}"
    export FORMATION_COHORT="${FORMATION_COHORT:-$PWD/.data/formation-build}"
    export FORMATION_WITH_CONTEXT="${FORMATION_WITH_CONTEXT:-1}"
    eval "$(python3 dev/formation-environment.py)"
    export GERBIL_LOADPATH="$GERBIL_PATH/lib:$GERBIL_LOADPATH"
    export GERBIL_BUILD_CORES=4
    export GERBIL_GCC="$(command -v "{{compiler}}")"
    export PKG_CONFIG_PATH="{{pkg_config_path}}"
    pkg-config --libs openssl >/dev/null
    mkdir -p .data/test-logs
    log="$(mktemp "$PWD/.data/test-logs/formation-ascent-build-XXXXXX")"
    cd "${FORMATION_DEPENDENCIES:-$PWD/.data/formation-dependencies}/gerbil-ascent"
    env -u SDKROOT timeout --verbose --signal=TERM --kill-after=5s 180s gxi -:max-heap=2G,debug=q build.ss compile 2>&1 | tee "$log"

build-project-formation:
    #!/usr/bin/env bash
    set -euo pipefail
    export FORMATION_COHORT="${FORMATION_COHORT:-$PWD/.data/formation-build}"
    export FORMATION_WITH_CONTEXT="${FORMATION_WITH_CONTEXT:-1}"
    eval "$(python3 dev/formation-environment.py)"
    export GERBIL_LOADPATH="$GERBIL_PATH/lib:$GERBIL_LOADPATH"
    export GERBIL_BUILD_CORES=4
    mkdir -p .data/test-logs
    log="$(mktemp .data/test-logs/formation-build-XXXXXX)"
    env -u SDKROOT timeout --verbose --signal=TERM --kill-after=5s 180s gxi -:max-heap=2G,debug=q formation-build.ss compile 2>&1 | tee "$log"

# Raw facts remain an explicitly untrusted design investigation interface.
investigate-formation-consequences output:
    #!/usr/bin/env bash
    set -euo pipefail
    test ! -e "{{output}}"
    export FORMATION_WITH_CONTEXT="${FORMATION_WITH_CONTEXT:-1}"
    eval "$(python3 dev/formation-environment.py)"
    mkdir -p .data/test-logs
    log="$(mktemp .data/test-logs/formation-consequences-XXXXXX)"
    env -u SDKROOT timeout --signal=TERM --kill-after=5s 120s gxi -:max-heap=2G,debug=q examples/library-formation-consequences.ss "{{output}}" 2>&1 | tee "$log"
