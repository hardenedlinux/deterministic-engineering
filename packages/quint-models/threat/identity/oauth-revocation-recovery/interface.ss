;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :clan/poo/object .def .o .get)
        "types.ss"
        "objects.ss"
        (only-in :deterministic-engineering/library/quint-profiles/objects
                 QuintModelSlotSpecs
                 QuintModelDefaultSlots
                 QuintModelGovernanceFloor))
(export OAuthRevocationRecovery)

(.def OAuthRevocationRecovery
  identity: 'oauth-revocation-recovery
  tags: '(quint
          quint.model
          quint.domain.threat
          quint.threat.identity
          quint.property.stateful
          quint.property.emergent-invariant
          quint.property.mbt-ready
          quint.failure.crash-recovery)
  slot-specs: QuintModelSlotSpecs
  defaults: QuintModelDefaultSlots
  governance-floor: QuintModelGovernanceFloor
  core:
  (.o
    admissions: (.o)
    scope-contract: (.get CatalogScopeContract value-contract)
    exports:
    (.o entry: OAuthRevocationRecoveryModel
        config: (.o entry: OAuthRevocationRecoveryModel)
        contracts: (.o config: CatalogConfigContract)))
  features: (.o))
