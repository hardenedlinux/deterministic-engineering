/* SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#ifndef DE_STABILITY_AGING_CONTRAST_H
#define DE_STABILITY_AGING_CONTRAST_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
  DE_EXIT_OK = 0,
  DE_EXIT_ERROR = 1,
  DE_EXIT_CANCEL = 2
} de_exit_kind_t;

typedef struct {
  size_t cap;
  size_t active;
  size_t held;
} de_handle_tracker_t;

typedef struct {
  size_t slot_cap;
  size_t max_retain_cap;
  size_t pooled_slots;
  size_t pooled_bytes;
} de_buf_pool_t;

typedef struct {
  size_t queue_cap;
  size_t retry_budget;
  size_t queue_depth;
  size_t retries_pending;
  size_t shed_count;
  bool congested;
} de_retry_ctrl_t;

/* Bad aging patterns (SM2/SM3/SM4/SM5): */
void bad_run_handle_cycle(de_handle_tracker_t *t, de_exit_kind_t outcome);
void bad_pool_return(de_buf_pool_t *p, size_t buf_bytes);
void bad_retry_admit(de_retry_ctrl_t *c);
void bad_retry_on_timeout(de_retry_ctrl_t *c);
void bad_retry_drain(de_retry_ctrl_t *c, size_t budget);

/* Deterministic steady-state boundaries: */
bool deterministic_run_handle_cycle(de_handle_tracker_t *t, de_exit_kind_t outcome);
bool deterministic_pool_return(de_buf_pool_t *p, size_t buf_bytes);
bool deterministic_retry_admit(de_retry_ctrl_t *c);
bool deterministic_retry_on_timeout(de_retry_ctrl_t *c);
void deterministic_retry_drain(de_retry_ctrl_t *c, size_t budget);

#endif
