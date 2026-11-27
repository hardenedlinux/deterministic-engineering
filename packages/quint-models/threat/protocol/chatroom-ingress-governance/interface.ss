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
(export ChatroomIngressGovernance)

(.def ChatroomIngressGovernance
  identity: 'chatroom-ingress-governance
  tags: '(quint
          quint.model
          quint.domain.threat
          quint.threat.protocol
          quint.property.stateful
          quint.property.emergent-invariant
          quint.property.mbt-ready
          quint.failure.authorization-bypass)
  slot-specs: QuintModelSlotSpecs
  defaults: QuintModelDefaultSlots
  governance-floor: QuintModelGovernanceFloor
  core:
  (.o
    admissions: (.o)
    scope-contract: (.get (library-catalog-scope-contract 'chatroom-ingress-governance/scope) value-contract)
    exports:
    (.o entry: ChatroomIngressGovernanceModel
        config: (.o entry: ChatroomIngressGovernanceModel)
        contracts: (.o config: ThreatCatalogConfigContract)))
  features: (.o))
