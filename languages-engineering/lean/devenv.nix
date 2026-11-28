# SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
#
# SPDX-License-Identifier: LGPL-2.1-or-later

{ pkgs, ... }:
{
  # Lean 4 / Lake language engineering toolchain.
  packages = [
    pkgs.elan
  ];
}
