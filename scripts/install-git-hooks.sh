#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
#
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Worktree-safe installer for deterministic-engineering root & subtree Git hooks.
# Usage:
#   scripts/install-git-hooks.sh [--auto|--worktree|--repo|--status|--uninstall]

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
GIT_DIR="$(git rev-parse --git-dir)"
GIT_COMMON_DIR="$(git rev-parse --git-common-dir)"
HOOKS_DIR=".githooks"

is_linked_worktree() {
  local abs_git abs_common
  abs_git="$(cd "$REPO_ROOT" && cd "$GIT_DIR" && pwd -P)"
  abs_common="$(cd "$REPO_ROOT" && cd "$GIT_COMMON_DIR" && pwd -P)"
  [ "$abs_git" != "$abs_common" ]
}

ensure_executables() {
  local h
  for h in "$REPO_ROOT/.githooks"/* "$REPO_ROOT"/packages/*/.githooks/*; do
    [ -f "$h" ] && chmod +x "$h"
  done
}

show_status() {
  local wt_flag="no"
  if is_linked_worktree; then
    wt_flag="yes"
  fi
  echo "repo_root=$REPO_ROOT"
  echo "linked_worktree=$wt_flag"
  echo "worktree_config_enabled=$(git config --bool extensions.worktreeconfig 2>/dev/null || echo false)"
  echo "effective_hooksPath=$(git config --show-origin core.hooksPath 2>/dev/null || echo '<unset>')"
  echo "root_hooks:"
  for h in "$REPO_ROOT/.githooks"/*; do
    [ -f "$h" ] && echo "  - ${h#"$REPO_ROOT/"}"
  done
  echo "subtree_hooks:"
  for h in "$REPO_ROOT"/packages/*/.githooks/*; do
    [ -f "$h" ] && echo "  - ${h#"$REPO_ROOT/"}"
  done
}

MODE="${1:---auto}"

case "$MODE" in
  --status)
    show_status
    ;;
  --worktree)
    ensure_executables
    git config extensions.worktreeconfig true
    git config --worktree core.hooksPath "$HOOKS_DIR"
    echo "[install-git-hooks] Configured worktree-scoped core.hooksPath=$HOOKS_DIR"
    ;;
  --repo)
    ensure_executables
    git config --local core.hooksPath "$HOOKS_DIR"
    echo "[install-git-hooks] Configured repo-scoped core.hooksPath=$HOOKS_DIR"
    ;;
  --auto)
    ensure_executables
    if is_linked_worktree; then
      git config extensions.worktreeconfig true
      git config --worktree core.hooksPath "$HOOKS_DIR"
      echo "[install-git-hooks] Detected linked worktree; configured worktree-scoped core.hooksPath=$HOOKS_DIR"
    else
      git config --local core.hooksPath "$HOOKS_DIR"
      echo "[install-git-hooks] Configured repo-scoped core.hooksPath=$HOOKS_DIR"
    fi
    ;;
  --uninstall)
    if is_linked_worktree && [ "$(git config --bool extensions.worktreeconfig 2>/dev/null || echo false)" = "true" ]; then
      git config --worktree --unset core.hooksPath 2>/dev/null || true
    fi
    git config --local --unset core.hooksPath 2>/dev/null || true
    echo "[install-git-hooks] Unset core.hooksPath"
    ;;
  *)
    echo "Usage: $0 [--auto|--worktree|--repo|--status|--uninstall]" >&2
    exit 2
    ;;
esac
