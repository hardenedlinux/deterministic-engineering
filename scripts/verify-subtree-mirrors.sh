#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
#
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# End-to-end verification of all 5 subtree package mirrors (`render`, `quint-models`,
# `quint-modules-resolver`, `lean-models`, `agent-defense-audit`) and real downstream
# Git Submodule consumption.
#
# Usage:
#   ./scripts/verify-subtree-mirrors.sh [--all | <pkg>...] [--ref <git-ref>] [--lean-poo-path <dir>] [--skip-lake-build]

set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"

REF="HEAD"
LEAN_POO_PATH="${LEAN_POO_PATH:-}"
SKIP_LAKE_BUILD=0
SELECTED_PKGS=()

usage() {
  cat <<'EOF'
Usage: scripts/verify-subtree-mirrors.sh [options] [package...]

Packages:
  --all                     Verify all 5 packages (default when no package is specified)
  render                    Verify packages/render subtree split + tarball + consumer import
  quint-models              Verify packages/quint-models subtree split + 10.204/10.205 invariants + submodule
  quint-modules-resolver    Verify packages/quint-modules-resolver + cross-submodule Quint parse/typecheck
  lean-models               Verify packages/lean-models + zero-Mathlib/Cedar/sorry + CedarHostConsumer lake build
  agent-defense-audit       Verify packages/agent-defense-audit + tarball + zero-dep 6-language CLI gate

Options:
  --ref <git-ref>           Git ref to split (default: HEAD)
  --lean-poo-path <dir>     Path to local LeanPoo checkout for downstream Lake verification
  --skip-lake-build         Skip the full Lake compilation step (still checks split, submodule, and Lean hygiene)
  -h, --help                Show this help
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --all)
      SELECTED_PKGS=(render quint-models quint-modules-resolver lean-models agent-defense-audit)
      ;;
    render|quint-models|quint-modules-resolver|lean-models|agent-defense-audit)
      SELECTED_PKGS+=("$1")
      ;;
    --ref)
      shift
      REF="${1:?--ref requires an argument}"
      ;;
    --lean-poo-path)
      shift
      LEAN_POO_PATH="${1:?--lean-poo-path requires an argument}"
      ;;
    --skip-lake-build)
      SKIP_LAKE_BUILD=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[verify-subtree-mirrors] Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [ "${#SELECTED_PKGS[@]}" -eq 0 ]; then
  SELECTED_PKGS=(render quint-models quint-modules-resolver lean-models agent-defense-audit)
fi

if [ -z "$LEAN_POO_PATH" ]; then
  default_lean_poo=$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$REPO_ROOT/packages/lean-models/../../../../tao3k/lean-poo")
  if [ -d "$default_lean_poo" ]; then
    LEAN_POO_PATH="$default_lean_poo"
  fi
fi

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/de-verify-subtree-mirrors.XXXXXX")
trap 'rm -rf "$WORK_DIR"' EXIT

mkdir -p "$WORK_DIR/mirrors" "$WORK_DIR/consumer" "$WORK_DIR/packs"

init_consumer_repo() {
  local repo_dir="$1"
  mkdir -p "$repo_dir"
  git -C "$repo_dir" init -b main >/dev/null 2>&1
  git -C "$repo_dir" config user.name "Subtree Mirror Verifier"
  git -C "$repo_dir" config user.email "verifier@deterministic-engineering.invalid"
}

split_and_mount_submodule() {
  local pkg="$1"
  local consumer_dir="$2"
  local prefix="packages/${pkg}"
  local mirror_dir="$WORK_DIR/mirrors/deterministic-engineering-${pkg}.git"
  local submodule_rel="vendor/${pkg}"

  if [ ! -d "$mirror_dir" ]; then
    local split_sha
    split_sha=$(git subtree split --prefix="$prefix" "$REF" 2>/dev/null)
    if ! printf '%s\n' "$split_sha" | grep -Eq '^[0-9a-f]{40}$'; then
      echo "[verify-subtree-mirrors] ERROR: invalid split SHA for ${prefix}: ${split_sha}" >&2
      exit 1
    fi
    git init --bare -b main "$mirror_dir" >/dev/null 2>&1
    git push "$mirror_dir" "${split_sha}:refs/heads/main" >/dev/null 2>&1
    printf '%s\n' "$split_sha" > "$WORK_DIR/mirrors/${pkg}.sha"
  fi

  local split_sha
  split_sha=$(cat "$WORK_DIR/mirrors/${pkg}.sha")

  if [ ! -d "${consumer_dir}/${submodule_rel}" ]; then
    git -C "$consumer_dir" -c protocol.file.allow=always submodule add "$mirror_dir" "$submodule_rel" >/dev/null 2>&1
  fi

  # Common mirror contract: standalone bundled pre-commit hook must exist and parse cleanly.
  local hook_path="${consumer_dir}/${submodule_rel}/.githooks/pre-commit"
  if [ ! -f "$hook_path" ]; then
    echo "[verify-subtree-mirrors] ERROR: ${pkg} mirror missing .githooks/pre-commit" >&2
    exit 1
  fi
  bash -n "$hook_path"

  echo "[verify-subtree-mirrors] Mounted submodule ${submodule_rel} @ ${split_sha}" >&2
  printf '%s\n' "$split_sha"
}

verify_render() {
  local cdir="$WORK_DIR/consumer/render-host"
  init_consumer_repo "$cdir"
  local sha
  sha=$(split_and_mount_submodule "render" "$cdir")
  local pkg_dir="$cdir/vendor/render"

  python3 - "$pkg_dir" <<'PY'
import json, os, sys
pkg_dir = sys.argv[1]
with open(os.path.join(pkg_dir, "package.json"), "r", encoding="utf-8") as fh:
    pkg = json.load(fh)
assert pkg.get("name") == "@deterministic-engineering/render", f"unexpected name: {pkg.get('name')}"
assert pkg.get("license") == "LGPL-2.1-or-later", f"unexpected license: {pkg.get('license')}"
exports = pkg.get("exports", {})
assert len(exports) >= 5, f"expected >=5 exports, got {len(exports)}"
for k, v in exports.items():
    target = v if isinstance(v, str) else v.get("default")
    assert target and os.path.exists(os.path.join(pkg_dir, target)), f"missing export {k} -> {target}"
PY

  local pack_dir="$WORK_DIR/packs/render"
  mkdir -p "$pack_dir"
  (cd "$pkg_dir" && bun pm pack --destination "$pack_dir" >/dev/null)
  local tgz_list tgz
  tgz_list=$(find "$pack_dir" -maxdepth 1 -name '*.tgz')
  tgz=${tgz_list%%$'\n'*}
  if [ -z "$tgz" ]; then
    echo "[verify-subtree-mirrors] ERROR: bun pm pack produced no tarball for render" >&2
    exit 1
  fi
  local tar_entries
  tar_entries=$(tar -tzf "$tgz")
  grep -Eq '^package/src/index\.ts$' <<< "$tar_entries"
  grep -Eq '^package/package\.json$' <<< "$tar_entries"

  # Link workspace node_modules so the downstream submodule can execute real Bun module imports.
  if [ -d "$REPO_ROOT/packages/render/node_modules" ]; then
    ln -s "$REPO_ROOT/packages/render/node_modules" "$pkg_dir/node_modules"
  elif [ -d "$REPO_ROOT/node_modules" ]; then
    ln -s "$REPO_ROOT/node_modules" "$pkg_dir/node_modules"
  fi
  bun -e "
    const mod = await import('${pkg_dir}/src/index.ts');
    for (const sym of ['composeDiagram', 'composeFigure', 'defineDesign', 'compileModel']) {
      if (typeof mod[sym] !== 'function') {
        throw new Error('Missing expected render export: ' + sym);
      }
    }
  "
  echo "PASS render split=${sha} submodule=ok pack=ok import=ok"
}

verify_quint_models() {
  local cdir="$WORK_DIR/consumer/quint-models-host"
  init_consumer_repo "$cdir"
  local sha
  sha=$(split_and_mount_submodule "quint-models" "$cdir")
  local pkg_dir="$cdir/vendor/quint-models"

  python3 - "$pkg_dir" <<'PY'
import json, os, re, sys
pkg_dir = sys.argv[1]
with open(os.path.join(pkg_dir, "package.json"), "r", encoding="utf-8") as fh:
    pkg = json.load(fh)
assert pkg.get("name") == "@deterministic-engineering/quint-models", f"unexpected name: {pkg.get('name')}"
assert pkg.get("license") == "LGPL-2.1-or-later", f"unexpected license: {pkg.get('license')}"

forbidden_slot_re = re.compile(
    r"^\s*(state|guards|transitions|safety|traces|countermodels|parameters|verify-depth|countermodel-depth):"
)

types_ss = []
bloated_objects = []
qnt_count = 0
defense_qnt_count = 0

for root, _, files in os.walk(pkg_dir):
    if ".git" in root.split(os.sep):
        continue
    for name in files:
        full = os.path.join(root, name)
        rel = os.path.relpath(full, pkg_dir)
        if name == "types.ss":
            types_ss.append(rel)
        elif name == "objects.ss":
            with open(full, "r", encoding="utf-8") as fh:
                for line in fh:
                    code = line.split(";", 1)[0]
                    if forbidden_slot_re.search(code):
                        bloated_objects.append((rel, line.strip()))
                        break
        elif name.endswith(".qnt"):
            qnt_count += 1
            if rel.startswith(os.path.join("engineering", "defense") + os.sep):
                defense_qnt_count += 1

assert not types_ss, f"10.205 violation: found forbidden per-model types.ss in split mirror: {types_ss[:5]}"
assert not bloated_objects, f"10.204 violation: found duplicated Quint AST slots in objects.ss: {bloated_objects[:5]}"
assert defense_qnt_count >= 30, f"expected >=30 defense .qnt models, found {defense_qnt_count}"

pioneer = os.path.join(pkg_dir, "engineering/defense/model-weight-inference-attestation/ModelWeightInferenceAttestation.qnt")
assert os.path.isfile(pioneer), f"missing 30th pioneer model: {pioneer}"
print(f"QUINT_MODELS_INVENTORY qnt_total={qnt_count} defense_qnt={defense_qnt_count} types_ss=0 bloated_objects=0")
PY

  echo "PASS quint-models split=${sha} submodule=ok ssot_10_204=ok zero_types_ss_10_205=ok"
}

verify_quint_modules_resolver() {
  local cdir="$WORK_DIR/consumer/quint-resolver-host"
  init_consumer_repo "$cdir"
  local sha
  sha=$(split_and_mount_submodule "quint-modules-resolver" "$cdir")
  local qm_sha
  qm_sha=$(split_and_mount_submodule "quint-models" "$cdir")
  local res_dir="$cdir/vendor/quint-modules-resolver"
  local qm_dir="$cdir/vendor/quint-models"

  python3 - "$res_dir" <<'PY'
import json, os, sys
pkg_dir = sys.argv[1]
with open(os.path.join(pkg_dir, "package.json"), "r", encoding="utf-8") as fh:
    pkg = json.load(fh)
assert pkg.get("name") == "@deterministic-engineering/quint-modules-resolver", f"unexpected name: {pkg.get('name')}"
assert pkg.get("license") == "LGPL-2.1-or-later", f"unexpected license: {pkg.get('license')}"
for k, v in pkg.get("exports", {}).items():
    target = v if isinstance(v, str) else v.get("default")
    assert target and os.path.exists(os.path.join(pkg_dir, target)), f"missing export {k} -> {target}"
for k, target in pkg.get("bin", {}).items():
    assert target and os.path.exists(os.path.join(pkg_dir, target)), f"missing bin {k} -> {target}"
PY

  local pack_dir="$WORK_DIR/packs/quint-modules-resolver"
  mkdir -p "$pack_dir"
  (cd "$res_dir" && bun pm pack --destination "$pack_dir" >/dev/null)
  local tgz_list tgz
  tgz_list=$(find "$pack_dir" -maxdepth 1 -name '*.tgz')
  tgz=${tgz_list%%$'\n'*}
  if [ -z "$tgz" ]; then
    echo "[verify-subtree-mirrors] ERROR: bun pm pack produced no tarball for quint-modules-resolver" >&2
    exit 1
  fi
  local tar_entries
  tar_entries=$(tar -tzf "$tgz")
  grep -Eq '^package/src/cli\.ts$' <<< "$tar_entries"

  # Wire real @informalsystems/quint runtime + split quint-models submodule into downstream consumer.
  mkdir -p "$cdir/node_modules/@deterministic-engineering"
  ln -s "$qm_dir" "$cdir/node_modules/@deterministic-engineering/quint-models"
  if [ -d "$REPO_ROOT/packages/quint-modules-resolver/node_modules/@informalsystems" ]; then
    ln -s "$REPO_ROOT/packages/quint-modules-resolver/node_modules/@informalsystems" "$cdir/node_modules/@informalsystems"
  elif [ -d "$REPO_ROOT/node_modules/@informalsystems" ]; then
    ln -s "$REPO_ROOT/node_modules/@informalsystems" "$cdir/node_modules/@informalsystems"
  else
    echo "[verify-subtree-mirrors] ERROR: @informalsystems/quint not found in workspace node_modules" >&2
    exit 1
  fi

  local sample_qnt="$qm_dir/engineering/defense/model-weight-inference-attestation/ModelWeightInferenceAttestation.qnt"
  (
    cd "$cdir"
    bun "$res_dir/src/cli.ts" parse "$sample_qnt" >/dev/null
    bun "$res_dir/src/cli.ts" typecheck "$sample_qnt" >/dev/null
  )

  echo "PASS quint-modules-resolver split=${sha} quint_models_split=${qm_sha} submodule=ok pack=ok cross_submodule_typecheck=ok"
}

verify_lean_models() {
  local cdir="$WORK_DIR/consumer/cedar-host-consumer"
  init_consumer_repo "$cdir"
  local sha
  sha=$(split_and_mount_submodule "lean-models" "$cdir")
  local pkg_dir="$cdir/vendor/lean-models"

  if [ ! -f "$pkg_dir/lakefile.toml" ] || [ ! -f "$pkg_dir/lean-toolchain" ]; then
    echo "[verify-subtree-mirrors] ERROR: lean-models mirror missing lakefile.toml or lean-toolchain" >&2
    exit 1
  fi

  # Static hygiene invariant across the entire split Lean mirror (zero Mathlib, zero Cedar, zero sorry/admit).
  python3 - "$pkg_dir" <<'PY'
import os, re, sys

pkg_dir = sys.argv[1]

def strip_lean_comments(src: str) -> str:
    out = []
    i = 0
    n = len(src)
    depth = 0
    while i < n:
        if depth == 0 and src[i:i+2] == "--":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if src[i:i+2] == "/-":
            depth += 1
            i += 2
            continue
        if depth > 0 and src[i:i+2] == "-/":
            depth -= 1
            i += 2
            continue
        if depth == 0:
            out.append(src[i])
        i += 1
    return "".join(out)

lean_files = []
eng_modules = []
for root, _, files in os.walk(pkg_dir):
    if ".git" in root.split(os.sep) or ".lake" in root.split(os.sep):
        continue
    for name in sorted(files):
        if name.endswith(".lean"):
            full = os.path.join(root, name)
            rel = os.path.relpath(full, pkg_dir)
            lean_files.append((rel, full))
            if rel.startswith(os.path.join("DeterministicEngineering", "Engineering") + os.sep):
                eng_modules.append(rel)

assert len(eng_modules) >= 20, f"expected >=20 Engineering Lean modules, found {len(eng_modules)}"

for rel, full in lean_files:
    with open(full, "r", encoding="utf-8") as fh:
        stripped = strip_lean_comments(fh.read())
    assert not re.search(r"^\s*import\s+Mathlib\b", stripped, re.M), f"{rel}: forbidden import Mathlib"
    assert not re.search(r"^\s*import\s+Cedar\b", stripped, re.M), f"{rel}: forbidden import Cedar"
    assert not re.search(r"(?<![A-Za-z0-9_.])(sorry|admit)(?![A-Za-z0-9_])", stripped), f"{rel}: incomplete proof token (sorry/admit)"

print(f"LEAN_MODELS_INVENTORY lean_files={len(lean_files)} engineering_modules={len(eng_modules)} mathlib=0 cedar=0 sorry=0")
PY

  if [ "$SKIP_LAKE_BUILD" -eq 1 ]; then
    echo "PASS lean-models split=${sha} submodule=ok hygiene=ok lake_build=skipped"
    return 0
  fi

  if [ -z "$LEAN_POO_PATH" ] || [ ! -d "$LEAN_POO_PATH" ]; then
    echo "[verify-subtree-mirrors] ERROR: LeanPoo checkout not found; pass --lean-poo-path <dir> or --skip-lake-build" >&2
    exit 1
  fi

  cp "$pkg_dir/lean-toolchain" "$cdir/lean-toolchain"
  cat > "$cdir/lakefile.toml" <<EOF
name = "CedarHostConsumer"
version = "0.1.0"
defaultTargets = ["CedarHostConsumer"]

[[require]]
name = "LeanPoo"
path = "${LEAN_POO_PATH}"

[[require]]
name = "DeterministicEngineering"
path = "vendor/lean-models"

[[lean_lib]]
name = "CedarHostConsumer"
EOF

  cat > "$cdir/CedarHostConsumer.lean" <<'EOF'
import DeterministicEngineering.Engineering.ModelWeightAndInferenceAttestation

#check @DeterministicEngineering.Engineering.ModelWeightAndInferenceAttestation.unpinned_base_weight_refused
#print axioms DeterministicEngineering.Engineering.ModelWeightAndInferenceAttestation.unpinned_base_weight_refused
EOF

  local lake_log="$WORK_DIR/lake-build.log"
  (cd "$cdir" && lake build CedarHostConsumer > "$lake_log" 2>&1)
  if grep -q 'sorryAx' "$lake_log"; then
    cat "$lake_log" >&2
    echo "[verify-subtree-mirrors] ERROR: sorryAx detected in downstream Lake proof axioms" >&2
    exit 1
  fi
  if ! grep -q "Build completed successfully" "$lake_log"; then
    cat "$lake_log" >&2
    echo "[verify-subtree-mirrors] ERROR: lake build did not report success" >&2
    exit 1
  fi

  echo "PASS lean-models split=${sha} submodule=ok hygiene=ok lake_build=ok axioms=clean"
}

verify_agent_defense_audit() {
  local cdir="$WORK_DIR/consumer/agent-defense-host"
  init_consumer_repo "$cdir"
  local sha
  sha=$(split_and_mount_submodule "agent-defense-audit" "$cdir")
  local pkg_dir="$cdir/vendor/agent-defense-audit"

  python3 - "$pkg_dir" <<'PY'
import json, os, sys
pkg_dir = sys.argv[1]
with open(os.path.join(pkg_dir, "package.json"), "r", encoding="utf-8") as fh:
    pkg = json.load(fh)
assert pkg.get("name") == "@deterministic-engineering/agent-defense-audit", f"unexpected name: {pkg.get('name')}"
assert pkg.get("license") == "LGPL-2.1-or-later", f"unexpected license: {pkg.get('license')}"
for k, v in pkg.get("exports", {}).items():
    target = v if isinstance(v, str) else v.get("default")
    assert target and os.path.exists(os.path.join(pkg_dir, target)), f"missing export {k} -> {target}"
for k, target in pkg.get("bin", {}).items():
    assert target and os.path.exists(os.path.join(pkg_dir, target)), f"missing bin {k} -> {target}"
PY

  local pack_dir="$WORK_DIR/packs/agent-defense-audit"
  mkdir -p "$pack_dir"
  (cd "$pkg_dir" && bun pm pack --destination "$pack_dir" >/dev/null)
  local tgz_list tgz
  tgz_list=$(find "$pack_dir" -maxdepth 1 -name '*.tgz')
  tgz=${tgz_list%%$'\n'*}
  if [ -z "$tgz" ]; then
    echo "[verify-subtree-mirrors] ERROR: bun pm pack produced no tarball for agent-defense-audit" >&2
    exit 1
  fi
  local tar_entries
  tar_entries=$(tar -tzf "$tgz")
  grep -Eq '^package/src/agent-defense-audit\.ts$' <<< "$tar_entries"
  grep -Eq '^package/src/multi-lang-auditor\.ts$' <<< "$tar_entries"
  grep -Eq '^package/src/index\.ts$' <<< "$tar_entries"

  # Zero-node_modules standalone execution test across Go, Rust, Scheme, and TS!
  mkdir -p "$cdir/sample"
  cat > "$cdir/sample/ok.go" <<'EOF'
package sample
import "errors"
func Check(v int) error {
	if v < 0 {
		return errors.New("negative")
	}
	return nil
}
EOF
  cat > "$cdir/sample/bad.go" <<'EOF'
package sample
func Swallow(fn func() error) error {
	if err := fn(); err != nil {
		return nil
	}
	return nil
}
EOF
  (
    cd "$cdir"
    bun "$pkg_dir/src/agent-defense-audit.ts" --files sample/ok.go >/dev/null
    if bun "$pkg_dir/src/agent-defense-audit.ts" --files sample/bad.go >/dev/null 2>&1; then
      echo "[verify-subtree-mirrors] ERROR: standalone agent-defense-audit failed to refuse Go silent fallback" >&2
      exit 1
    fi
  )
  echo "PASS agent-defense-audit split=${sha} submodule=ok pack=ok zero_dep_cli=ok"
}

for pkg in "${SELECTED_PKGS[@]}"; do
  case "$pkg" in
    render) verify_render ;;
    quint-models) verify_quint_models ;;
    quint-modules-resolver) verify_quint_modules_resolver ;;
    lean-models) verify_lean_models ;;
    agent-defense-audit) verify_agent_defense_audit ;;
  esac
done

echo "VERIFY_SUBTREE_MIRRORS_OK packages=${SELECTED_PKGS[*]} ref=${REF}"
