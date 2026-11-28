;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/execution/state-rollback/objects
                 StateRollbackModel)
        "../../../support/quint-model-qualification.ss")
(export state-rollback-qualification-test)

(def state-rollback-qualification-test
  (make-quint-model-qualification-suite "state-rollback" StateRollbackModel))
