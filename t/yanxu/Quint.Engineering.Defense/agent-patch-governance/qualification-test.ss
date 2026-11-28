;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/agent-patch-governance/objects
                 AgentPatchGovernanceModel)
        "../../../support/quint-model-qualification.ss")
(export agent-patch-governance-qualification-test)

(def agent-patch-governance-qualification-test
  (make-quint-model-qualification-suite "agent-patch-governance" AgentPatchGovernanceModel))
