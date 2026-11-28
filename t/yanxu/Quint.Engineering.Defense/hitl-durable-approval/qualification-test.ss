;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/hitl-durable-approval/objects
                 HitlDurableApprovalModel)
        "../../../support/quint-model-qualification.ss")
(export hitl-durable-approval-qualification-test)

(def hitl-durable-approval-qualification-test
  (make-quint-model-qualification-suite "hitl-durable-approval" HitlDurableApprovalModel))
