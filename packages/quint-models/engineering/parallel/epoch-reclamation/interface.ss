;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :clan/poo/object .def .o .get)
        (only-in :deterministic-engineering/types library-catalog-scope-contract)
        (only-in :deterministic-engineering/library/quint-methods/types EngineeringCatalogConfigContract)
        "objects.ss"
        (only-in :deterministic-engineering/library/quint-profiles/objects
                 QuintModelSlotSpecs
                 QuintModelDefaultSlots
                 QuintModelGovernanceFloor))
(export EpochReclamation)

(.def EpochReclamation
  identity: 'epoch-reclamation
  tags: '(quint
          quint.model
          quint.domain.engineering
          quint.engineering.parallel
          quint.property.stateful
          quint.property.emergent-invariant
          quint.property.mbt-ready
          quint.failure.use-after-free
          defense.mutability.negative-domain
          defense.property.guard-declared)
  slot-specs: QuintModelSlotSpecs
  defaults: QuintModelDefaultSlots
  governance-floor: QuintModelGovernanceFloor
  core:
  (.o
    admissions: (.o)
    scope-contract: (.get (library-catalog-scope-contract 'epoch-reclamation/scope) value-contract)
    exports:
    (.o entry: EpochReclamationModel
        config: (.o entry: EpochReclamationModel)
        contracts: (.o config: EngineeringCatalogConfigContract)))
  features: (.o))
