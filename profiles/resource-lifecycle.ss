;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; -*- Gerbil -*-
(import
  :clan/poo/object)
(export
  LifecycleProfile
  LargerPayloadProfile)
(.def LifecycleProfile
  identity: 'resource-64
  capacity: 1
  queue: 1
  item: 64
  fixed: 0
  budget: 256
  cache-bytes: 0
  tokio-workers: 1
  rayon-workers: 1
  cpu-budget: 1
  factors: '(bounded-retention
             tokio
             rayon
             normal-handoff
             admission-cancellation
             abandoned-result
             caller-abort
             cleanup-full
             caller-owned-permit)
  lock: "captured-by-native-method"
  runtime: "current-thread/rayon1/unwind"
  workload: (string-append "controlled-six-case-suite/" (number->string item))
  inventory: "unique-owned-payload/permit")
(.def (LargerPayloadProfile @ LifecycleProfile)
  identity: 'resource-128
  item: 128)
