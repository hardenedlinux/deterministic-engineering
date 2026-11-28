/* SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include <assert.h>
#include <stddef.h>
#include "stability.h"

int main(void) {
  const size_t NORMAL_BYTES = 1024;
  const size_t SPIKE_BYTES = 65536;
  const size_t SLOT_CAP = 4;
  const size_t QUEUE_CAP = 4;
  const size_t RETRY_BUDGET = 1;

  de_handle_tracker_t bad_h = { .cap = 200, .active = 0, .held = 0 };
  de_handle_tracker_t good_h = { .cap = 16, .active = 0, .held = 0 };
  de_buf_pool_t bad_p = { .slot_cap = SLOT_CAP, .max_retain_cap = NORMAL_BYTES, .pooled_slots = 0, .pooled_bytes = 0 };
  de_buf_pool_t good_p = { .slot_cap = SLOT_CAP, .max_retain_cap = NORMAL_BYTES, .pooled_slots = 0, .pooled_bytes = 0 };
  de_retry_ctrl_t bad_r = { .queue_cap = QUEUE_CAP, .retry_budget = RETRY_BUDGET, .queue_depth = 0, .retries_pending = 0, .shed_count = 0, .congested = false };
  de_retry_ctrl_t good_r = { .queue_cap = QUEUE_CAP, .retry_budget = RETRY_BUDGET, .queue_depth = 0, .retries_pending = 0, .shed_count = 0, .congested = false };

  for (size_t c = 1; c <= 120; ++c) {
    de_exit_kind_t outcome = (c % 7 == 0) ? DE_EXIT_ERROR : ((c % 11 == 0) ? DE_EXIT_CANCEL : DE_EXIT_OK);
    bad_run_handle_cycle(&bad_h, outcome);
    deterministic_run_handle_cycle(&good_h, outcome);

    size_t sz = (c % 15 == 0) ? SPIKE_BYTES : NORMAL_BYTES;
    bad_pool_return(&bad_p, sz);
    deterministic_pool_return(&good_p, sz);

    bad_retry_admit(&bad_r);
    deterministic_retry_admit(&good_r);
    if (c % 5 == 0) {
      bad_r.congested = true;
      good_r.congested = true;
      bad_retry_admit(&bad_r);
      deterministic_retry_admit(&good_r);
      for (int k = 0; k < 3; ++k) {
        bad_retry_on_timeout(&bad_r);
        deterministic_retry_on_timeout(&good_r);
      }
    }
    bad_retry_drain(&bad_r, QUEUE_CAP);
    deterministic_retry_drain(&good_r, QUEUE_CAP);
  }

  /* Bad aging implementation exhibits all three aging failure modes: */
  assert(bad_h.held > 0);
  assert(bad_p.pooled_bytes > SLOT_CAP * NORMAL_BYTES);
  assert(bad_r.queue_depth > 0);

  /* Deterministic steady-state implementation preserves exact zero drift & strict ceilings: */
  assert(good_h.active == 0);
  assert(good_h.held == 0);
  assert(good_p.pooled_slots <= SLOT_CAP);
  assert(good_p.pooled_bytes <= SLOT_CAP * NORMAL_BYTES);
  assert(good_r.queue_depth == 0);
  assert(good_r.retries_pending == 0);
  assert(!good_r.congested);
  assert(good_r.shed_count > 0);
  return 0;
}
