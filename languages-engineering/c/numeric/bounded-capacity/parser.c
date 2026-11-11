// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "capacity.h"

/* A parser admits a payload only after accounting for its framing bytes. */
int parser_fits(uint32_t payload, uint32_t header, uint32_t available)
{
  uint32_t total = 0;
  return capacity_total(payload, header, &total) && total <= available;
}
