;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/agent-ifc-capability/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export agent-ifc-capability-qualification-test)

(def agent-ifc-capability-qualification-test
  (make-quint-model-qualification-suite
    "agent-ifc-capability"
    AgentIfcCapabilityModel
    (.get ThreatModelProfiles agent-ifc-capability)))
