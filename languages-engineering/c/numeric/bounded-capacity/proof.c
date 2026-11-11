// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "capacity.h"

extern uint32_t nondet_u32(void);

/* Contract enforcement supplies arbitrary states satisfying its precondition.
 * The separate capacity_harness checks the original caller-visible state. */
void contract_harness(void)
{
  uint32_t out = nondet_u32();
  capacity_total(nondet_u32(), nondet_u32(), &out);
}

void capacity_harness(void)
{
  uint32_t a = nondet_u32();
  uint32_t b = nondet_u32();
  uint32_t initial = nondet_u32();
  uint32_t out = initial;
  int ok = capacity_total(a, b, &out);

  __CPROVER_assert(ok == ((uint64_t)a + b <= UINT32_MAX), "capacity.result");
  __CPROVER_assert(ok ? (uint64_t)out == (uint64_t)a + b : out == initial,
                   "capacity.output-and-failure-frame");
}

void callers_harness(void)
{
  uint32_t a = nondet_u32();
  uint32_t b = nondet_u32();
  uint32_t available = nondet_u32();
  int expected = (uint64_t)a + b <= available;

  __CPROVER_assert(parser_fits(a, b, available) == expected, "parser.admission");
  __CPROVER_assert(pool_fits(a, b, available) == expected, "pool.admission");
}
