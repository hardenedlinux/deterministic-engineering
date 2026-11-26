;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/release-sod-rollback/objects
                 ReleaseSodRollbackModel)
        "../../../support/quint-model-qualification.ss")
(export release-sod-rollback-qualification-test)

(def release-sod-rollback-qualification-test
  (make-quint-model-qualification-suite "release-sod-rollback" ReleaseSodRollbackModel))
