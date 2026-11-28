;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/slow-consumer-eviction/objects
                 SlowConsumerEvictionModel)
        "../../../support/quint-model-qualification.ss")
(export slow-consumer-eviction-qualification-test)

(def slow-consumer-eviction-qualification-test
  (make-quint-model-qualification-suite "slow-consumer-eviction" SlowConsumerEvictionModel))
