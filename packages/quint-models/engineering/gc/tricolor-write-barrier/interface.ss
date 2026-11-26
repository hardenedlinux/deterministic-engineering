;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :clan/poo/object .def .o .get)
        "types.ss"
        "objects.ss"
        (only-in :deterministic-engineering/library/quint-profiles/objects
                 QuintModelSlotSpecs
                 QuintModelDefaultSlots
                 QuintModelGovernanceFloor))
(export TricolorWriteBarrier)

(.def TricolorWriteBarrier
  identity: 'tricolor-write-barrier
  tags: '(quint
          quint.model
          quint.domain.engineering
          quint.engineering.gc
          quint.property.stateful
          quint.property.emergent-invariant
          quint.property.mbt-ready
          quint.failure.live-object-sweep)
  slot-specs: QuintModelSlotSpecs
  defaults: QuintModelDefaultSlots
  governance-floor: QuintModelGovernanceFloor
  core:
  (.o
    admissions: (.o)
    scope-contract: (.get CatalogScopeContract value-contract)
    exports:
    (.o entry: TricolorWriteBarrierModel
        config: (.o entry: TricolorWriteBarrierModel)
        contracts: (.o config: CatalogConfigContract)))
  features: (.o))
