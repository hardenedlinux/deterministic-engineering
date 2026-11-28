;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/ui-render-window-budget/objects
                 UiRenderWindowBudgetModel)
        "../../../support/quint-model-qualification.ss")
(export ui-render-window-budget-qualification-test)

(def ui-render-window-budget-qualification-test
  (make-quint-model-qualification-suite "ui-render-window-budget" UiRenderWindowBudgetModel))
