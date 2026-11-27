# SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
#
# SPDX-License-Identifier: LGPL-2.1-or-later

{ pkgs, ... }:
{
  # TypeScript / Bun language engineering runtime.
  packages = [
    pkgs.bun
  ];
}
