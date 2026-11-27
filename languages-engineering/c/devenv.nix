# SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
#
# SPDX-License-Identifier: LGPL-2.1-or-later

{ ... }:
{
  # C language engineering subdir module; preserves host/SDK clang & cbmc bindings.
  env.DE_C_SUBDIR_ENABLED = "1";
}
