;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/execution/agent-ifc-capability/objects
                 AgentIfcCapabilityModel)
        "../../../support/quint-model-qualification.ss")
(export agent-ifc-capability-qualification-test)

(def agent-ifc-capability-qualification-test
  (make-quint-model-qualification-suite "agent-ifc-capability" AgentIfcCapabilityModel))
