;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/identity/workload-identity-rotation/objects
                 WorkloadIdentityRotationModel)
        "../../../support/quint-model-qualification.ss")
(export workload-identity-rotation-qualification-test)

(def workload-identity-rotation-qualification-test
  (make-quint-model-qualification-suite "workload-identity-rotation" WorkloadIdentityRotationModel))
