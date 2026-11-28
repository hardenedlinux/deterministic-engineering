# SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
#
# SPDX-License-Identifier: LGPL-2.1-or-later

{ ... }:
{
  # C++20 language engineering subdir module; preserves host/SDK clang++ bindings.
  env.DE_CPP_SUBDIR_ENABLED = "1";
}
