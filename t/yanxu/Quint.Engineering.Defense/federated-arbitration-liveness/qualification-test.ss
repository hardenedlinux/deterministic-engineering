;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/federated-arbitration-liveness/objects
                 FederatedArbitrationLivenessModel)
        "../../../support/quint-model-qualification.ss")
(export federated-arbitration-liveness-qualification-test)

(def federated-arbitration-liveness-qualification-test
  (make-quint-model-qualification-suite
    "federated-arbitration-liveness"
    FederatedArbitrationLivenessModel))
