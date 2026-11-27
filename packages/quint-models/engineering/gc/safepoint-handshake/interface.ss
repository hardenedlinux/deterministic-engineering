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
(export SafepointHandshake)

(.def SafepointHandshake
  identity: 'safepoint-handshake
  tags: '(quint
          quint.model
          quint.domain.engineering
          quint.engineering.gc
          quint.property.stateful
          quint.property.emergent-invariant
          quint.property.mbt-ready
          quint.failure.barrier-bypass
          defense.mutability.mutable-root
          defense.property.guard-declared)
  slot-specs: QuintModelSlotSpecs
  defaults: QuintModelDefaultSlots
  governance-floor: QuintModelGovernanceFloor
  core:
  (.o
    admissions: (.o)
    scope-contract: (.get (library-catalog-scope-contract 'safepoint-handshake/scope) value-contract)
    exports:
    (.o entry: SafepointHandshakeModel
        config: (.o entry: SafepointHandshakeModel)
        contracts: (.o config: EngineeringCatalogConfigContract)))
  features: (.o))
