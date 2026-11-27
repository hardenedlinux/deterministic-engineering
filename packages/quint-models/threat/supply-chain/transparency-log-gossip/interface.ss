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
(export TransparencyLogGossip)

(.def TransparencyLogGossip
  identity: 'transparency-log-gossip
  tags: '(quint
          quint.model
          quint.domain.threat
          quint.threat.supply-chain
          quint.property.stateful
          quint.property.emergent-invariant
          quint.property.mbt-ready
          quint.failure.equivocation
          defense.mutability.immutable
          defense.property.guard-declared)
  slot-specs: QuintModelSlotSpecs
  defaults: QuintModelDefaultSlots
  governance-floor: QuintModelGovernanceFloor
  core:
  (.o
    admissions: (.o)
    scope-contract: (.get (library-catalog-scope-contract 'transparency-log-gossip/scope) value-contract)
    exports:
    (.o entry: TransparencyLogGossipModel
        config: (.o entry: TransparencyLogGossipModel)
        contracts: (.o config: ThreatCatalogConfigContract)))
  features: (.o))
