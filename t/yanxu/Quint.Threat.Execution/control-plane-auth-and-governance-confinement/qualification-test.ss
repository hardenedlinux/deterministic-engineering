;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/execution/control-plane-auth-and-governance-confinement/objects
                 ControlPlaneAuthAndGovernanceConfinementModel)
        "../../../support/quint-model-qualification.ss")
(export control-plane-auth-and-governance-confinement-qualification-test)

(def control-plane-auth-and-governance-confinement-qualification-test
  (make-quint-model-qualification-suite
    "control-plane-auth-and-governance-confinement"
    ControlPlaneAuthAndGovernanceConfinementModel))
