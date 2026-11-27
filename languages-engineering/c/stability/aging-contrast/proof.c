/* SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include "stability.h"

extern size_t nondet_size_t(void);
extern int nondet_int(void);
extern bool nondet_bool(void);

int main(void) {
  /* 1. CBMC proof of SM2/SM4 handle conservation across arbitrary error/cancel/ok exits: */
  de_handle_tracker_t h = { .cap = 4, .active = 0, .held = 0 };
  for (int i = 0; i < 4; ++i) {
    int raw = nondet_int();
    de_exit_kind_t exit_kind = (raw == 0) ? DE_EXIT_OK : ((raw == 1) ? DE_EXIT_ERROR : DE_EXIT_CANCEL);
    (void)deterministic_run_handle_cycle(&h, exit_kind);
    assert(h.active == 0);
    assert(h.held == 0);
  }

  /* 2. CBMC proof of SM3 spike-independent capped pool conservation for ANY buf_bytes: */
  de_buf_pool_t p = { .slot_cap = 2, .max_retain_cap = 1024, .pooled_slots = 0, .pooled_bytes = 0 };
  for (int i = 0; i < 4; ++i) {
    size_t sz = nondet_size_t();
    (void)deterministic_pool_return(&p, sz);
    assert(p.pooled_slots <= p.slot_cap);
    assert(p.pooled_bytes <= p.pooled_slots * p.max_retain_cap);
    assert(p.pooled_bytes <= p.slot_cap * p.max_retain_cap);
  }

  /* 3. CBMC proof of SM5 overload shedding & retry-budget bounds: */
  de_retry_ctrl_t r = {
    .queue_cap = 2, .retry_budget = 1,
    .queue_depth = 0, .retries_pending = 0, .shed_count = 0, .congested = false
  };
  for (int i = 0; i < 4; ++i) {
    if (nondet_bool()) {
      (void)deterministic_retry_admit(&r);
    } else if (nondet_bool()) {
      r.congested = true;
      (void)deterministic_retry_on_timeout(&r);
    } else {
      deterministic_retry_drain(&r, 1);
    }
    assert(r.queue_depth <= r.queue_cap);
    assert(r.retries_pending <= r.retry_budget);
    assert(r.retries_pending <= r.queue_depth);
  }
  return 0;
}
