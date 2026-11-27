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
(export AtomicPersistenceFsyncEnvelope)

(.def AtomicPersistenceFsyncEnvelope
  identity: 'atomic-persistence-fsync-envelope
  tags: '(quint
          quint.model
          quint.domain.engineering
          quint.engineering.storage
          quint.property.stateful
          quint.property.emergent-invariant
          quint.property.mbt-ready
          quint.failure.crash-recovery
          defense.mutability.mutable-root
          defense.property.guard-declared)
  slot-specs: QuintModelSlotSpecs
  defaults: QuintModelDefaultSlots
  governance-floor: QuintModelGovernanceFloor
  core:
  (.o
    admissions: (.o)
    scope-contract: (.get (library-catalog-scope-contract 'atomic-persistence-fsync-envelope/scope) value-contract)
    exports:
    (.o entry: AtomicPersistenceFsyncEnvelopeModel
        config: (.o entry: AtomicPersistenceFsyncEnvelopeModel)
        contracts: (.o config: EngineeringCatalogConfigContract)))
  features: (.o))
