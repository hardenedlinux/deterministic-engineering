# SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
#
# SPDX-License-Identifier: LGPL-2.1-or-later

# Unified zero-hardcoding command surface for local development and GitHub Actions CI.
# - Native Scheme Yuanxu + Functional Fun-Flow engine: t/harness/funflow-exec.ss (`just flow ...`)
# - Portable zero-Gerbil CI worker (identical graph/tag algebra): t/harness/verify-framework.ts (`just verify ...`)
# Adding new Scheme/Quint/Lean/TS/C/C++/Rust/Go modules requires ZERO edits here or in CI.
set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

export GERBIL_BUILD_CORES := env_var_or_default("GERBIL_BUILD_CORES", `if command -v gxi >/dev/null 2>&1; then gxi -:max-heap=2G -e '(display (##core-count))'; else nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4; fi`)
export GAMBOPT := if env_var_or_default("GAMBOPT", "") == "" { "max-heap=2G,debug=q" } else if env_var("GAMBOPT") =~ "(^|,)max-heap=2G,debug=q$" { env_var("GAMBOPT") } else { env_var("GAMBOPT") + ",max-heap=2G,debug=q" }

gerbil_homebrew_runtime := `gerbil_executable="$(command -v gerbil 2>/dev/null || true)"; if [ -n "$gerbil_executable" ] && realpath "$gerbil_executable" | grep -F '/opt/homebrew/Cellar/' >/dev/null; then printf true; else printf false; fi`
homebrew_openssl_prefix := `if command -v brew >/dev/null 2>&1; then brew --prefix openssl@3 2>/dev/null || true; fi`
darwin_openssl_prefix := env_var_or_default("OPENSSL_PREFIX", homebrew_openssl_prefix)
gerbil_darwin_env := if os() == "macos" { if gerbil_homebrew_runtime == "true" { "env -u SDKROOT -u DEVELOPER_DIR -u CPATH -u LIBRARY_PATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u MACOSX_DEPLOYMENT_TARGET -u DYLD_LIBRARY_PATH -u DYLD_FALLBACK_LIBRARY_PATH COMPILER_PATH=/usr/bin CPATH='" + darwin_openssl_prefix + "/include' LIBRARY_PATH='" + darwin_openssl_prefix + "/lib' PKG_CONFIG_PATH=\"" + darwin_openssl_prefix + "/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}\"" } else { "env" } } else { "env" }

# ── 1. Native Gerbil Package Lifecycle ────────────────────────────────────────

deps:
    timeout --foreground --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q deps --install

deps-update:
    timeout --foreground --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxi -e '(import (only-in :gerbil/tools/gxpkg pkg-update pkg-install with-pkg-build-env)) (with-pkg-build-env (for-each (lambda (dependency) (pkg-update dependency) (pkg-install dependency)) (pgetq depend: (call-with-input-file "gerbil.pkg" read) (quote ()))))'

build-dependency package:
    timeout --foreground --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxpkg build "{{ package }}"

build:
    timeout --foreground --signal=TERM --kill-after=5s 300s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q build

build-mount mount:
    timeout --foreground --signal=TERM --kill-after=5s 180s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxi ./build.ss compile "--mount={{ mount }}"

build-file module:
    timeout --foreground --signal=TERM --kill-after=5s 120s {{ gerbil_darwin_env }} gerbil -:max-heap=2G,debug=q env gxi ./build.ss compile "--file={{ module }}"

# ── 2. Canonical Yuanxu + Functional Fun-Flow Execution Control Plane ─────────
# Compiles discovered Yuanxu/polyglot units into a real Fun-Flow DAG with
# SHA-256 content-addressed caching (--cache), O(Delta) git-diff slicing (--impact),
# parallel green-thread waves (--jobs=N), dry-run planning (--plan), and replay validation.

flow *args:
    t/harness/run-gxtest.sh script none t/harness/funflow-exec.ss {{args}}

flow-list:
    just flow --list

flow-plan *args:
    just flow --plan {{args}}

flow-impact *args:
    just flow --impact {{args}}

# ── 3. Portable Zero-Gerbil Verification Surface (Single Source of Truth for CI) ─
# Exact same zero-hardcoding graph discovery & tag algebra without requiring Gerbil.

verify *args:
    bun t/harness/verify-framework.ts run {{args}}

verify-list:
    bun t/harness/verify-framework.ts list

verify-plan *args:
    bun t/harness/verify-framework.ts run --plan {{args}}

verify-impact *args:
    bun t/harness/verify-framework.ts run --impact {{args}}

verify-matrix target="quint" *flags:
    bun t/harness/verify-framework.ts matrix {{target}} {{flags}}

verify-lang lang domain="" *flags:
    bun t/harness/verify-framework.ts run --lang={{lang}} {{ if domain != "" { "--domain=" + domain } else { "" } }} {{flags}}

# Declarative tag-driven verification gates (zero hardcoded file/model/script lists).
check-defense *flags:
    just verify --tag=defense {{flags}}

check-stability *flags:
    just verify --tag=stability,go:concurrency,quint.engineering.concurrency,quint.engineering.gc,lean.core.stability {{flags}}

check-multi-method *flags:
    just verify --tag=funflow {{flags}}

check-quint *flags:
    just verify --domain=quint {{flags}}

check-quint-shard domain subdomains cache_dir="" *flags:
    bun packages/quint-modules-resolver/src/cli.ts run-fleet packages/quint-models --domain={{domain}} --subdomain={{subdomains}} --concurrency=4 {{ if cache_dir != "" { "--cache=" + cache_dir } else { "" } }} {{flags}}
    bun packages/quint-modules-resolver/src/cli.ts run-fleet packages/quint-models --domain={{domain}} --subdomain={{subdomains}} --mbt-audit --n-traces=12 --seed=7 --min-coverage=1.0 --concurrency=4 {{ if cache_dir != "" { "--cache=" + cache_dir } else { "" } }} {{flags}}

check-lean *flags:
    just verify --lang=lean {{flags}}

check-render *flags:
    just verify --domain=render {{flags}}

check-render-consumer:
    #!/usr/bin/env bash
    set -euo pipefail
    render_version=$(bun -e 'import metadata from "./packages/render/package.json"; process.stdout.write(metadata.version)')
    export RENDER_EXPECTED_VERSION="$render_version"
    split_sha=$(git subtree split --prefix=packages/render HEAD)
    mirror_work=$(mktemp -d)
    render_consumer=$(mktemp -d)
    trap 'rm -rf "$mirror_work" "$render_consumer"' EXIT
    git archive "$split_sha" | tar -x -C "$mirror_work"
    tarball=$(cd "$mirror_work" && bun pm pack --quiet | tail -n 1)
    cd "$render_consumer"
    bun init -y
    bun add "${mirror_work}/${tarball}"
    bun -e 'import metadata from "@deterministic-engineering/render/package.json"; import {compileModel} from "@deterministic-engineering/render"; import {encodeWebP} from "@deterministic-engineering/render/export"; if(metadata.version!==process.env.RENDER_EXPECTED_VERSION)throw new Error("Wrong Git package version"); const compiled=await compileModel({"consumer.d2":"Library -> Consumer"},"consumer.d2"); if(compiled.model.relations.length!==1)throw new Error("Git-installed worker did not compile the consumer model"); const webp=await encodeWebP(Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAAAACXBIWXMAAAPoAAAD6AG1e1JrAAAADklEQVQImWP4DwUMMAYAj4IP8cvlVgcAAAAASUVORK5CYII=","base64")); if(Buffer.from(webp.bytes).toString("ascii",8,12)!=="WEBP")throw new Error("Git-installed native WebP encoder failed");'

fleet-quint:
    bun run fleet:quint

mbt-quint:
    bun run mbt:quint

# ── 4. AI Agent PR & Library Auditors ─────────────────────────────────────────

audit-agent-patch *args:
    bun packages/agent-defense-audit/src/agent-defense-audit.ts {{ if args == "" { "--diff" } else { args } }}

audit-agent-stability *args:
    bun languages-engineering/ts/stability/aging-contrast/agent-stability-audit.ts {{ if args == "" { "--diff" } else { args } }}

audit-leanpoo-fleet *args:
    bun packages/agent-defense-audit/src/leanpoo-fleet-audit.ts {{ args }}

# ── 5. Atomic Gerbil / Yuanxu Scheme Runners ──────────────────────────────────

test-file path pattern=".*" timeout_s="120s":
    t/harness/run-gxtest.sh file "{{path}}" "{{pattern}}" "{{timeout_s}}"

test-dir dir timeout_s="120s" glob="*-test.ss":
    t/harness/run-gxtest.sh dir "{{dir}}" "{{timeout_s}}" "{{glob}}"

formation-test-file path cases:
    t/harness/run-gxtest.sh formation "{{path}}" "{{cases}}"

test-de-layout:
    just test-file t/integration/module-publication/loader-ownership-test.ss

test-quint-models *flags:
    just flow --tag=quint.model {{flags}}

test-source-contracts pattern=".*" path="t/yanxu/Library/source-contracts/contracts-test.ss":
    just test-file "{{path}}" "{{pattern}}"

test-gateway:
    t/harness/run-gxtest.sh suites t/yanxu/Library/gateway-profiles/gateway-library-test.ss 120s

# Core native Gerbil/Yuanxu suite driven declaratively through Yuanxu + Fun-Flow.
test *flags:
    just flow --mount=Library,Integration --skip=funflow {{flags}}

test-project-formation:
    just formation-test-file t/yanxu/Library/library-formation-profiles/project-formation-test.ss 14

test-backpressure-reassessment:
    #!/usr/bin/env bash
    set -euo pipefail
    : "${BACKPRESSURE_REASSESSMENT_RUNS:?Provide the actual reassessment runs artifact}"
    : "${BACKPRESSURE_REVIEW_SOURCES:?Provide the actual runtime source artifact}"
    : "${BACKPRESSURE_ACCEPTANCE:?Provide the actual acceptance artifact}"
    if [[ -z "${BACKPRESSURE_REASSESSMENT_REVIEW_OUTPUT:-}" ]]; then
      mkdir -p .data/test-runs
      export BACKPRESSURE_REASSESSMENT_REVIEW_OUTPUT="$(mktemp -d "$PWD/.data/test-runs/review-XXXXXX")/results"
    fi
    just test-file t/integration/backpressure/reassessment-test.ss ".*" 180s

test-producer-source-custody:
    #!/usr/bin/env bash
    set -euo pipefail
    : "${BACKPRESSURE_ACCEPTANCE:?Provide the actual acceptance artifact}"
    mkdir -p .data/test-runs
    export BACKPRESSURE_CUSTODY_OUTPUT="$(mktemp -d "$PWD/.data/test-runs/custody-XXXXXX")/results"
    just test-file t/integration/backpressure/producer-source-custody-test.ss ".*" 180s

# ── 6. Evidence Investigation & Offline Air-Gapped Attestation Verifiers ──────

investigate-source-contracts output:
    t/harness/run-gxtest.sh script 180s t/support/source-contract-evidence.ss "{{output}}" "$(realpath "$(command -v cbmc)")" "$(realpath "$(command -v goto-cc)")" "$(realpath "$(command -v goto-instrument)")" "$(realpath "$(command -v clang)")" "$(realpath "$(command -v clang++)")"

investigate-resource output:
    #!/usr/bin/env bash
    set -euo pipefail
    test ! -e "{{output}}"
    t/harness/run-gxtest.sh script 600s t/support/resource-lifecycle-evidence.ss "{{output}}" "${RESOURCE_CARGO:-$("$HOME/.cargo/bin/rustup" which cargo)}" "${RESOURCE_RUSTC:-$("$HOME/.cargo/bin/rustup" which rustc)}" "${RESOURCE_QUINT:-$(realpath "$(command -v quint)")}" "${RESOURCE_LEAN:-$(elan which lean)}"
    RESOURCE_REAL_REPORT="{{output}}/report.json" just test-file t/yanxu/Library/resource-lifecycle-profiles/lifecycle-test.ss

investigate-resource-integration output sysml:
    #!/usr/bin/env bash
    set -euo pipefail
    test ! -e "{{output}}" && test -x "{{sysml}}"
    t/harness/run-gxtest.sh script 600s t/support/resource-integration-evidence.ss "{{output}}" "${RESOURCE_CARGO:-$("$HOME/.cargo/bin/rustup" which cargo)}" "${RESOURCE_RUSTC:-$("$HOME/.cargo/bin/rustup" which rustc)}" "${RESOURCE_QUINT:-$(realpath "$(command -v quint)")}" "${RESOURCE_LEAN:-$(elan which lean)}" "$(realpath "{{sysml}}")"

investigate-backpressure-reassessment output:
    t/harness/run-gxtest.sh script 240s t/support/backpressure-reassessment-evidence.ss "{{output}}" "${RESOURCE_CARGO:-$("$HOME/.cargo/bin/rustup" which cargo)}" "${RESOURCE_RUSTC:-$("$HOME/.cargo/bin/rustup" which rustc)}"

investigate-project-formation output:
    test ! -e "{{output}}" && t/harness/run-gxtest.sh script 120s t/support/library-formation.ss "{{output}}"

investigate-formation-consequences output:
    test ! -e "{{output}}" && t/harness/run-gxtest.sh script 120s t/support/library-formation-consequences.ss "{{output}}"

investigate-multi-method output cache_dir="" subject="process-tree-reclamation":
    test ! -e "{{output}}" && t/harness/run-gxtest.sh script 300s t/support/verification-flow-runner.ss "{{output}}" "{{cache_dir}}" "{{subject}}"

fleet-multi-method output cache_dir="":
    test ! -e "{{output}}" && t/harness/run-gxtest.sh script 420s t/support/verification-flow-runner.ss --fleet "{{output}}" "{{cache_dir}}"

plan-multi-method-fleet cache_dir="":
    t/harness/run-gxtest.sh script none t/support/verification-flow-runner.ss --plan "{{cache_dir}}"

impact-multi-method *files:
    t/harness/run-gxtest.sh script none t/support/verification-flow-runner.ss --impact {{files}}

verify-multi-method-report report trust_store:
    t/harness/run-gxtest.sh script none t/support/offline-attestation-verifier.ss --verify-report "{{report}}" "{{trust_store}}"

verify-multi-method-fleet fleet_report trust_store:
    t/harness/run-gxtest.sh script none t/support/offline-attestation-verifier.ss --verify-fleet "{{fleet_report}}" "{{trust_store}}"

verify-multi-method-cache cache_file trust_store:
    t/harness/run-gxtest.sh script none t/support/offline-attestation-verifier.ss --verify-cache "{{cache_file}}" "{{trust_store}}"

verify-multi-method-trust-store trust_store *flags:
    t/harness/run-gxtest.sh script none t/support/offline-attestation-verifier.ss {{flags}} --verify-trust-store "{{trust_store}}"

export-multi-method-trust-bundle out *args:
    t/harness/run-gxtest.sh script none t/support/offline-attestation-verifier.ss --export-trust-bundle "{{out}}" {{args}}

# Portable zero-dependency (<100ms, zero Gerbil, zero OpenSSL) Bun/TS offline attestation CLI & 25-control gate.
verify-multi-method-fast *args:
    bun t/harness/offline-attestation-verifier.ts {{args}}

check-offline-verifier:
    bun test t/harness/offline-attestation-verifier.test.ts
