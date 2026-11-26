;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/durable-saga-budget/objects
                 DurableSagaBudgetModel)
        "../../../support/quint-model-qualification.ss")
(export durable-saga-budget-qualification-test)

(def durable-saga-budget-qualification-test
  (make-quint-model-qualification-suite "durable-saga-budget" DurableSagaBudgetModel))
