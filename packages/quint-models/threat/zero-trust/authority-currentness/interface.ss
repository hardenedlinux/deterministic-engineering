;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :clan/poo/object .def .o .get)
        (only-in :deterministic-engineering/types library-catalog-scope-contract)
        (only-in :deterministic-engineering/library/quint-methods/types ThreatCatalogConfigContract)
        "objects.ss"
        (only-in :deterministic-engineering/library/quint-profiles/objects
                 QuintModelSlotSpecs
                 QuintStatelessModelDefaultSlots))
(export AuthorityCurrentness)

(.def AuthorityCurrentness
  identity: 'authority-currentness
  tags: '(quint
          quint.model
          quint.domain.threat
          quint.threat.zero-trust
          quint.property.stateless
          quint.failure.stale-authority
          defense.mutability.mutable-root)
  slot-specs: QuintModelSlotSpecs
  defaults: QuintStatelessModelDefaultSlots
  core:
  (.o
    admissions: (.o)
    scope-contract: (.get (library-catalog-scope-contract 'authority-currentness/scope) value-contract)
    exports:
    (.o entry: AuthorityCurrentnessModel
        config: (.o entry: AuthorityCurrentnessModel)
        contracts: (.o config: ThreatCatalogConfigContract)))
  features: (.o))
