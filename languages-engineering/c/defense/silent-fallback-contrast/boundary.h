/* SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#ifndef DE_DEFENSE_SILENT_FALLBACK_CONTRAST_H
#define DE_DEFENSE_SILENT_FALLBACK_CONTRAST_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
  DE_BOUNDARY_OK = 0,
  DE_BOUNDARY_SETUP_DEFECT = 1,
  DE_BOUNDARY_REFUSED_OVERFLOW = 2,
  DE_BOUNDARY_REFUSED_CAPACITY = 3
} de_boundary_status_t;

typedef struct {
  size_t used;
  size_t cap;
} de_budget_t;

/* P1 anti-pattern: masks overflow or NULL pointer by silently returning 0 ("safe default"). */
size_t bad_defensive_reserve_total(const de_budget_t *b, size_t delta);

/* C2 deterministic boundary: fail-closed status + explicit checked output pointer. */
de_boundary_status_t deterministic_reserve_total(const de_budget_t *b, size_t delta, size_t *out_total);

#endif
