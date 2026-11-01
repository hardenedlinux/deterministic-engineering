;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-only

;;; -*- Gerbil -*-
(import
  :clan/poo/object)
(export
  LocalProfile
  Cap2Profile
  CacheProfile
  RetryProfile)

;; Small accounting fixtures, not measured bytes or optimal pool sizes.
;; Versions/features/targets from a real Cargo.lock must replace runtime before use.
(.def LocalProfile
  identity: 'C1
  tokio-workers: 2
  rayon-workers: 2
  cpu-budget: 4
  lock: "fixture/Cargo.lock-v1"
  capacity: 2
  queue: 2
  item: 64
  fixed: 128
  budget: 512
  cache-bytes: 0
  factors: '(bounded-retention tokio rayon)
  workload: "fixture/W-A"
  runtime: "fixture/tokio+rayon-config-v1"
  inventory: "fixture/owners-v1")
(.def (Cap2Profile @ LocalProfile)
  identity: 'C2
  capacity: 4)
(.def (CacheProfile @ LocalProfile)
  identity: 'C1-cache
  cache-bytes: 128
  factors: => (cut append <> '(cache)))
(.def (RetryProfile @ LocalProfile)
  identity: 'C1-retry
  factors: => (cut append <> '(retry)))
