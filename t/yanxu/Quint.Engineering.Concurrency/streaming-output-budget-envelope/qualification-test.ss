;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/streaming-output-budget-envelope/objects
                 StreamingOutputBudgetEnvelopeModel)
        "../../../support/quint-model-qualification.ss")
(export streaming-output-budget-envelope-qualification-test)

(def streaming-output-budget-envelope-qualification-test
  (make-quint-model-qualification-suite "streaming-output-budget-envelope" StreamingOutputBudgetEnvelopeModel))
