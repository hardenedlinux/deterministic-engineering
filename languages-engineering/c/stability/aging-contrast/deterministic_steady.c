/* SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include <stdint.h>
#include "stability.h"

bool deterministic_run_handle_cycle(de_handle_tracker_t *t, de_exit_kind_t outcome) {
  bool ok = false;
  if (!t || t->held > t->cap || t->active > t->held || t->held == t->cap) {
    return false;
  }
  t->active += 1;
  t->held += 1;

  if (outcome == DE_EXIT_ERROR) {
    ok = false;
    goto cleanup;
  }
  if (outcome == DE_EXIT_CANCEL) {
    ok = false;
    goto cleanup;
  }
  ok = true;

cleanup:
  /* Single deterministic cleanup boundary (SM2/SM4): every exit path releases ownership. */
  t->held -= 1;
  t->active -= 1;
  return ok;
}

bool deterministic_pool_return(de_buf_pool_t *p, size_t buf_bytes) {
  if (!p) return false;
  /* SM3 deterministic retain boundary: discard spike buffers and excess slots. */
  if (buf_bytes > p->max_retain_cap) {
    return false;
  }
  if (p->pooled_slots >= p->slot_cap) {
    return false;
  }
  if (p->pooled_bytes > SIZE_MAX - buf_bytes) {
    return false;
  }
  p->pooled_slots += 1;
  p->pooled_bytes += buf_bytes;
  return true;
}

bool deterministic_retry_admit(de_retry_ctrl_t *c) {
  if (!c) return false;
  if (c->congested || c->queue_depth >= c->queue_cap) {
    if (c->shed_count < SIZE_MAX) c->shed_count += 1;
    return false;
  }
  c->queue_depth += 1;
  return true;
}

bool deterministic_retry_on_timeout(de_retry_ctrl_t *c) {
  if (!c || !c->congested || c->queue_depth == 0) return false;
  if (c->retries_pending >= c->retry_budget || c->queue_depth >= c->queue_cap) {
    if (c->shed_count < SIZE_MAX) c->shed_count += 1;
    return false;
  }
  c->queue_depth += 1;
  c->retries_pending += 1;
  return true;
}

void deterministic_retry_drain(de_retry_ctrl_t *c, size_t budget) {
  if (!c) return;
  while (budget > 0 && c->queue_depth > 0) {
    c->queue_depth -= 1;
    if (c->retries_pending > 0) c->retries_pending -= 1;
    budget -= 1;
  }
  if (c->queue_depth == 0) c->congested = false;
}
