;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/saga-compensation-idempotency/objects
                 SagaCompensationModel)
        "../../../support/quint-model-qualification.ss")
(export saga-compensation-idempotency-qualification-test)

(def saga-compensation-idempotency-qualification-test
  (make-quint-model-qualification-suite "saga-compensation-idempotency" SagaCompensationModel))
