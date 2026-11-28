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
(export ProcessSignalLedgerAndFanoutConfinement)

(.def ProcessSignalLedgerAndFanoutConfinement
  identity: 'process-signal-ledger-and-fanout-confinement
  tags: '(quint
          quint.model
          quint.domain.threat
          quint.threat.execution
          quint.property.stateful
          quint.property.emergent-invariant
          quint.property.mbt-ready
          quint.failure.process-signal-ledger-fanout-confinement-bypass
          de.layer.threat)
  slot-specs: QuintModelSlotSpecs
  defaults: QuintModelDefaultSlots
  governance-floor: QuintModelGovernanceFloor
  core:
  (.o
    admissions: (.o)
    scope-contract: (.get (library-catalog-scope-contract 'process-signal-ledger-and-fanout-confinement/scope) value-contract)
    exports:
    (.o entry: ProcessSignalLedgerAndFanoutConfinementModel
        config: (.o entry: ProcessSignalLedgerAndFanoutConfinementModel)
        contracts: (.o config: ThreatCatalogConfigContract)))
  features: (.o))
