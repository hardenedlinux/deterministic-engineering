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
(export OutboundHttpRedirectSsrfConfinement)

(.def OutboundHttpRedirectSsrfConfinement
  identity: 'outbound-http-redirect-ssrf-confinement
  tags: '(quint
          quint.model
          quint.domain.threat
          quint.threat.protocol
          quint.property.stateful
          quint.property.emergent-invariant
          quint.property.mbt-ready
          quint.failure.ssrf
          defense.mutability.mutable-root
          defense.property.guard-declared)
  slot-specs: QuintModelSlotSpecs
  defaults: QuintModelDefaultSlots
  governance-floor: QuintModelGovernanceFloor
  core:
  (.o
    admissions: (.o)
    scope-contract: (.get (library-catalog-scope-contract 'outbound-http-redirect-ssrf-confinement/scope) value-contract)
    exports:
    (.o entry: OutboundHttpRedirectSsrfConfinementModel
        config: (.o entry: OutboundHttpRedirectSsrfConfinementModel)
        contracts: (.o config: ThreatCatalogConfigContract)))
  features: (.o))
