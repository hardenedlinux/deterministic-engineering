;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :clan/poo/object .def .o .get)
        "types.ss"
        "objects.ss"
        (only-in :deterministic-engineering/library/quint-profiles/objects
                 QuintModelSlotSpecs
                 QuintStatelessModelDefaultSlots))
(export Capabilities)

(.def Capabilities
  identity: 'capabilities
  tags: '(quint
          quint.model
          quint.domain.threat
          quint.threat.execution
          quint.property.stateless
          quint.failure.privilege-escalation
          defense.mutability.immutable)
  slot-specs: QuintModelSlotSpecs
  defaults: QuintStatelessModelDefaultSlots
  core:
  (.o
    admissions: (.o)
    scope-contract: (.get CatalogScopeContract value-contract)
    exports:
    (.o entry: CapabilitiesModel
        config: (.o entry: CapabilitiesModel)
        contracts: (.o config: CatalogConfigContract)))
  features: (.o))
