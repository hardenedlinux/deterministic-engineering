/* SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include "stability.h"

void bad_run_handle_cycle(de_handle_tracker_t *t, de_exit_kind_t outcome) {
  if (!t || t->held >= t->cap) return;
  t->active += 1;
  t->held += 1;
  if (outcome == DE_EXIT_ERROR) {
    /* SM2 ARB: early error return forgets to release handle. */
    t->active -= 1;
    return;
  }
  if (outcome == DE_EXIT_CANCEL) {
    /* SM4 ARB: cancel exit drops active work without releasing worker handle. */
    t->active -= 1;
    return;
  }
  t->held -= 1;
  t->active -= 1;
}

void bad_pool_return(de_buf_pool_t *p, size_t buf_bytes) {
  if (!p) return;
  /* SM3 ARB: uncapped return poisons pool with spike bytes and overflows slots. */
  p->pooled_slots += 1;
  p->pooled_bytes += buf_bytes;
}

void bad_retry_admit(de_retry_ctrl_t *c) {
  if (!c) return;
  /* SM5 ARB: admits unconditionally even under congestion. */
  c->queue_depth += 1;
}

void bad_retry_on_timeout(de_retry_ctrl_t *c) {
  if (!c || !c->congested || c->queue_depth == 0) return;
  /* SM5 ARB: unbounded retry amplification. */
  c->queue_depth += 1;
  c->retries_pending += 1;
}

void bad_retry_drain(de_retry_ctrl_t *c, size_t budget) {
  if (!c) return;
  while (budget > 0 && c->queue_depth > 0) {
    c->queue_depth -= 1;
    if (c->retries_pending > 0) c->retries_pending -= 1;
    budget -= 1;
  }
  if (c->queue_depth == 0) c->congested = false;
}
