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
(export DeviceAuthorization)

(.def DeviceAuthorization
  identity: 'device-authorization
  tags: '(quint
          quint.model
          quint.domain.threat
          quint.threat.identity
          quint.property.stateful
          quint.property.emergent-invariant
          quint.property.mbt-ready
          quint.failure.identity-confusion
          defense.mutability.negative-domain
          defense.property.guard-declared)
  slot-specs: QuintModelSlotSpecs
  defaults: QuintModelDefaultSlots
  governance-floor: QuintModelGovernanceFloor
  core:
  (.o
    admissions: (.o)
    scope-contract: (.get (library-catalog-scope-contract 'device-authorization/scope) value-contract)
    exports:
    (.o entry: DeviceAuthorizationModel
        config: (.o entry: DeviceAuthorizationModel)
        contracts: (.o config: ThreatCatalogConfigContract)))
  features: (.o))
