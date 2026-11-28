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
(export GovernancePolicyAndLatchAntirollback)

(.def GovernancePolicyAndLatchAntirollback
  identity: 'governance-policy-and-latch-antirollback
  tags: '(quint
          quint.model
          quint.domain.threat
          quint.threat.execution
          quint.property.stateful
          quint.property.emergent-invariant
          quint.property.mbt-ready
          quint.failure.governance-policy-latch-rollback
          de.layer.threat)
  slot-specs: QuintModelSlotSpecs
  defaults: QuintModelDefaultSlots
  governance-floor: QuintModelGovernanceFloor
  core:
  (.o
    admissions: (.o)
    scope-contract: (.get (library-catalog-scope-contract 'governance-policy-and-latch-antirollback/scope) value-contract)
    exports:
    (.o entry: GovernancePolicyAndLatchAntirollbackModel
        config: (.o entry: GovernancePolicyAndLatchAntirollbackModel)
        contracts: (.o config: ThreatCatalogConfigContract)))
  features: (.o))
