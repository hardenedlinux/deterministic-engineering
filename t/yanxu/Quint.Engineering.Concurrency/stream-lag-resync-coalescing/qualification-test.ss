;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/stream-lag-resync-coalescing/objects
                 StreamLagResyncCoalescingModel)
        "../../../support/quint-model-qualification.ss")
(export stream-lag-resync-coalescing-qualification-test)

(def stream-lag-resync-coalescing-qualification-test
  (make-quint-model-qualification-suite "stream-lag-resync-coalescing" StreamLagResyncCoalescingModel))
