;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/backpressure-memory/objects
                 BackpressureOwnersModel)
        "../../../support/quint-model-qualification.ss")
(export backpressure-memory-qualification-test)

(def backpressure-memory-qualification-test
  (make-quint-model-qualification-suite "backpressure-memory" BackpressureOwnersModel))
