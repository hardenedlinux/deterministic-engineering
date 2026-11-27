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
(export KeyRotationCryptoShredding)

(.def KeyRotationCryptoShredding
  identity: 'key-rotation-crypto-shredding
  tags: '(quint
          quint.model
          quint.domain.engineering
          quint.engineering.defense
          quint.property.stateful
          quint.property.emergent-invariant
          quint.property.mbt-ready
          quint.failure.key-lifecycle-violation
          de.layer.defense
          defense.pathology.misplaced
          defense.mutability.mutable-root
          defense.property.guard-declared
          defense.property.guard-pruned)
  slot-specs: QuintModelSlotSpecs
  defaults: QuintModelDefaultSlots
  governance-floor: QuintModelGovernanceFloor
  core:
  (.o
    admissions: (.o)
    scope-contract: (.get (library-catalog-scope-contract 'key-rotation-crypto-shredding/scope) value-contract)
    exports:
    (.o entry: KeyRotationCryptoShreddingModel
        config: (.o entry: KeyRotationCryptoShreddingModel)
        contracts: (.o config: EngineeringCatalogConfigContract)))
  features: (.o))
