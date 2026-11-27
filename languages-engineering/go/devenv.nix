# SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
#
# SPDX-License-Identifier: LGPL-2.1-or-later

{ pkgs, ... }:
{
  # Go language engineering toolchain (go vet, go test -race, testing/synctest).
  packages = [
    pkgs.go
  ];
}
