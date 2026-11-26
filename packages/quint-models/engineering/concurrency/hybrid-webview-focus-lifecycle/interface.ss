;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :clan/poo/object .def .o .get)
        "types.ss"
        "objects.ss"
        (only-in :deterministic-engineering/library/quint-profiles/objects
                 QuintModelSlotSpecs
                 QuintModelDefaultSlots
                 QuintModelGovernanceFloor))
(export HybridWebViewFocusLifecycle)

(.def HybridWebViewFocusLifecycle
  identity: 'hybrid-webview-focus-lifecycle
  tags: '(quint
          quint.model
          quint.domain.engineering
          quint.engineering.concurrency
          quint.property.stateful
          quint.property.emergent-invariant
          quint.property.mbt-ready
          quint.failure.webview-focus-stall
          defense.mutability.mutable-root
          defense.property.guard-declared)
  slot-specs: QuintModelSlotSpecs
  defaults: QuintModelDefaultSlots
  governance-floor: QuintModelGovernanceFloor
  core:
  (.o
    admissions: (.o)
    scope-contract: (.get CatalogScopeContract value-contract)
    exports:
    (.o entry: HybridWebViewFocusLifecycleModel
        config: (.o entry: HybridWebViewFocusLifecycleModel)
        contracts: (.o config: CatalogConfigContract)))
  features: (.o))
