/* SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include "boundary.h"

/* C2 Deterministic Trust-Boundary Replacement:
 * Distinguishes setup/contract defects (NULL pointers, violated struct invariant)
 * from arithmetic overflow and bounded-capacity refusal. Never clamps or returns
 * a silent zero fallback.
 */
de_boundary_status_t deterministic_reserve_total(const de_budget_t *b, size_t delta, size_t *out_total) {
  if (b == NULL || out_total == NULL || b->used > b->cap) {
    return DE_BOUNDARY_SETUP_DEFECT;
  }
  if (delta > SIZE_MAX - b->used) {
    return DE_BOUNDARY_REFUSED_OVERFLOW;
  }
  size_t next = b->used + delta;
  if (next > b->cap) {
    return DE_BOUNDARY_REFUSED_CAPACITY;
  }
  *out_total = next;
  return DE_BOUNDARY_OK;
}
