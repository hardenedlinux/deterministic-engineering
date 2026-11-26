/* SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include "boundary.h"

/* P1 Masking Anti-Pattern:
 * Swallows NULL pointer, broken invariant (used > cap), or arithmetic wraparound
 * by returning 0 as a "defensive fallback", making callers treat corruption as empty usage.
 */
size_t bad_defensive_reserve_total(const de_budget_t *b, size_t delta) {
  if (b == NULL || b->used > b->cap) {
    return 0;
  }
  if (delta > SIZE_MAX - b->used) {
    return 0;
  }
  size_t next = b->used + delta;
  if (next > b->cap) {
    return b->cap; /* Silent clamping masks capacity violation as success */
  }
  return next;
}
