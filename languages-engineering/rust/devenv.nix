# SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
#
# SPDX-License-Identifier: LGPL-2.1-or-later

{ pkgs, ... }:
{
  # Rust language engineering toolchain.
  packages = [
    pkgs.rustup
  ];
}
