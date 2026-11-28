;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/task-and-pool-cancellation-envelope/objects
                 TaskAndPoolCancellationEnvelopeModel)
        "../../../support/quint-model-qualification.ss")
(export task-and-pool-cancellation-envelope-qualification-test)

(def task-and-pool-cancellation-envelope-qualification-test
  (make-quint-model-qualification-suite "task-and-pool-cancellation-envelope" TaskAndPoolCancellationEnvelopeModel))
