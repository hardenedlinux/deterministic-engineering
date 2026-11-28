;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/execution/single-owner-graph-governance-confinement/objects
                 SingleOwnerGraphGovernanceConfinementModel)
        "../../../support/quint-model-qualification.ss")
(export single-owner-graph-governance-confinement-qualification-test)

(def single-owner-graph-governance-confinement-qualification-test
  (make-quint-model-qualification-suite
    "single-owner-graph-governance-confinement"
    SingleOwnerGraphGovernanceConfinementModel))
