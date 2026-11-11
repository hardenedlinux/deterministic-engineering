// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef DE_CAPACITY_H
#define DE_CAPACITY_H

#include <stdint.h>

/* Bytes throughout. Failure preserves the caller's output object. The wider
 * expression in the specification is mathematical accounting, not a wrapped
 * uint32_t addition. Native callers must provide a writable, live output. */
int capacity_total(uint32_t payload, uint32_t overhead, uint32_t *out)
#ifdef __CPROVER
  __CPROVER_requires(__CPROVER_is_fresh(out, sizeof(*out)))
  __CPROVER_assigns(*out)
  __CPROVER_ensures(__CPROVER_return_value == 0 || __CPROVER_return_value == 1)
  __CPROVER_ensures(
    (__CPROVER_return_value == 1) ==
    ((uint64_t)payload + (uint64_t)overhead <= UINT32_MAX))
  __CPROVER_ensures(
    __CPROVER_return_value == 1 ?
      (uint64_t)*out == (uint64_t)payload + (uint64_t)overhead :
      *out == __CPROVER_old(*out))
#endif
;

int parser_fits(uint32_t payload, uint32_t header, uint32_t available);
int pool_fits(uint32_t retained, uint32_t incoming, uint32_t budget);

#endif
