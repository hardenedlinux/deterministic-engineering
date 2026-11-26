;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/shared-context-governance/objects
                 SharedContextGovernanceModel)
        "../../../support/quint-model-qualification.ss")
(export shared-context-governance-qualification-test)

(def shared-context-governance-qualification-test
  (make-quint-model-qualification-suite "shared-context-governance" SharedContextGovernanceModel))
