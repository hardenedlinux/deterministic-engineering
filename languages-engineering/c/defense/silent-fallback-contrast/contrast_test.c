/* SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include <assert.h>
#include <stdint.h>
#include "boundary.h"

int main(void) {
  de_budget_t ok = { .used = 4, .cap = 10 };
  de_budget_t corrupt = { .used = 12, .cap = 10 };
  size_t out = 999;

  /* Bad defensive implementation masks corruption, overflow, and over-capacity as plausible integers: */
  assert(bad_defensive_reserve_total(NULL, 1) == 0);
  assert(bad_defensive_reserve_total(&corrupt, 1) == 0);
  assert(bad_defensive_reserve_total(&ok, SIZE_MAX) == 0);
  assert(bad_defensive_reserve_total(&ok, 20) == 10);

  /* Deterministic boundary exposes each distinct failure class and leaves out untouched on error: */
  assert(deterministic_reserve_total(NULL, 1, &out) == DE_BOUNDARY_SETUP_DEFECT);
  assert(out == 999);
  assert(deterministic_reserve_total(&corrupt, 1, &out) == DE_BOUNDARY_SETUP_DEFECT);
  assert(out == 999);
  assert(deterministic_reserve_total(&ok, SIZE_MAX, &out) == DE_BOUNDARY_REFUSED_OVERFLOW);
  assert(out == 999);
  assert(deterministic_reserve_total(&ok, 20, &out) == DE_BOUNDARY_REFUSED_CAPACITY);
  assert(out == 999);

  /* Valid bounded reservation succeeds cleanly: */
  assert(deterministic_reserve_total(&ok, 5, &out) == DE_BOUNDARY_OK);
  assert(out == 9);
  return 0;
}
