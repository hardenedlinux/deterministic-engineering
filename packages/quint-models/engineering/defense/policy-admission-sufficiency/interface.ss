;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :clan/poo/object .def .o .get)
        "types.ss"
        "objects.ss"
        (only-in :deterministic-engineering/library/quint-profiles/objects
                 QuintModelSlotSpecs
                 QuintModelDefaultSlots
                 QuintModelGovernanceFloor))
(export PolicyAdmissionSufficiency)

(.def PolicyAdmissionSufficiency
  identity: 'policy-admission-sufficiency
  tags: '(quint
          quint.model
          quint.domain.engineering
          quint.engineering.defense
          quint.property.stateful
          quint.property.emergent-invariant
          quint.property.mbt-ready
          quint.failure.policy-bypass
          de.layer.defense
          defense.pathology.masking
          defense.pathology.over-blocking
          defense.pathology.bloat
          defense.mutability.immutable
          defense.property.guard-declared
          defense.property.guard-pruned)
  slot-specs: QuintModelSlotSpecs
  defaults: QuintModelDefaultSlots
  governance-floor: QuintModelGovernanceFloor
  core:
  (.o
    admissions: (.o)
    scope-contract: (.get CatalogScopeContract value-contract)
    exports:
    (.o entry: PolicyAdmissionSufficiencyModel
        config: (.o entry: PolicyAdmissionSufficiencyModel)
        contracts: (.o config: CatalogConfigContract)))
  features: (.o))
