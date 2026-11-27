# SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
#
# SPDX-License-Identifier: LGPL-2.1-or-later

{ pkgs, ... }:
{
  # Core cross-language orchestration tools; language-specific toolchains live
  # in their owning subdir modules under languages-engineering/<lang>/devenv.nix
  # and are composed via `imports:` in devenv.yaml.
  packages = [
    pkgs.just
    pkgs.jq
    pkgs.coreutils
  ];

  # Optional per-language profiles (`devenv -P go shell`, etc.) mirror subdir ownership.
  profiles = {
    go.module = import ./languages-engineering/go/devenv.nix;
    rust.module = import ./languages-engineering/rust/devenv.nix;
    lean.module = import ./languages-engineering/lean/devenv.nix;
    ts.module = import ./languages-engineering/ts/devenv.nix;
    c.module = import ./languages-engineering/c/devenv.nix;
    cpp.module = import ./languages-engineering/cpp/devenv.nix;
  };
}
