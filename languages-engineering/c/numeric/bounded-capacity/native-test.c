// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "capacity.h"
#include <assert.h>

int main(void)
{
  /* Literal boundary gold: independent of the production implementation. */
  static const struct {
    uint32_t a, b, available, total;
    int ok, fits;
  } cases[] = {
    {0, 0, 0, 0, 1, 1},
    {100, 8, 107, 108, 1, 0},
    {100, 8, 108, 108, 1, 1},
    {UINT32_MAX, 0, UINT32_MAX, UINT32_MAX, 1, 1},
    {UINT32_MAX, 1, UINT32_MAX, 77, 0, 0},
    {UINT32_MAX - 3, 4, UINT32_MAX, 77, 0, 0}
  };

  for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    uint32_t out = 77;
    assert(capacity_total(cases[i].a, cases[i].b, &out) == cases[i].ok);
    assert(out == cases[i].total);
    assert(parser_fits(cases[i].a, cases[i].b, cases[i].available) == cases[i].fits);
    assert(pool_fits(cases[i].a, cases[i].b, cases[i].available) == cases[i].fits);
  }
  return 0;
}
