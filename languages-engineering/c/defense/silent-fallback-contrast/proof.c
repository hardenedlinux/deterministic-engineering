/* SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include <assert.h>
#include <stdint.h>
#include "boundary.h"

size_t nondet_size(void);

int main(void) {
  de_budget_t b;
  b.used = nondet_size();
  b.cap = nondet_size();
  size_t delta = nondet_size();
  size_t out = 77;

  de_boundary_status_t st = deterministic_reserve_total(&b, delta, &out);

  if (b.used > b.cap) {
    assert(st == DE_BOUNDARY_SETUP_DEFECT);
    assert(out == 77);
  } else if (delta > SIZE_MAX - b.used) {
    assert(st == DE_BOUNDARY_REFUSED_OVERFLOW);
    assert(out == 77);
  } else if (b.used + delta > b.cap) {
    assert(st == DE_BOUNDARY_REFUSED_CAPACITY);
    assert(out == 77);
  } else {
    assert(st == DE_BOUNDARY_OK);
    assert(out == b.used + delta);
    assert(out <= b.cap);
  }
  return 0;
}
