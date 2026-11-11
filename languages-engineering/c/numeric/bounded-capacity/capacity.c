// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "capacity.h"

int capacity_total(uint32_t payload, uint32_t overhead, uint32_t *out)
{
  if (payload > UINT32_MAX - overhead)
    return 0;

  *out = payload + overhead;
  return 1;
}
