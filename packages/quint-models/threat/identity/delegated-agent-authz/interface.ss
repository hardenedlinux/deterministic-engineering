;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :clan/poo/object .def .o .get)
        (only-in :deterministic-engineering/types library-catalog-scope-contract)
        (only-in :deterministic-engineering/library/quint-methods/types ThreatCatalogConfigContract)
        "objects.ss"
        (only-in :deterministic-engineering/library/quint-profiles/objects
                 QuintModelSlotSpecs
                 QuintModelDefaultSlots
                 QuintModelGovernanceFloor))
(export DelegatedAgentAuthz)

(.def DelegatedAgentAuthz
  identity: 'delegated-agent-authz
  tags: '(quint
          quint.model
          quint.domain.threat
          quint.threat.identity
          quint.property.stateful
          quint.property.emergent-invariant
          quint.property.mbt-ready
          quint.failure.privilege-escalation)
  slot-specs: QuintModelSlotSpecs
  defaults: QuintModelDefaultSlots
  governance-floor: QuintModelGovernanceFloor
  core:
  (.o
    admissions: (.o)
    scope-contract: (.get (library-catalog-scope-contract 'delegated-agent-authz/scope) value-contract)
    exports:
    (.o entry: DelegatedAgentAuthzModel
        config: (.o entry: DelegatedAgentAuthzModel)
        contracts: (.o config: ThreatCatalogConfigContract)))
  features: (.o))
