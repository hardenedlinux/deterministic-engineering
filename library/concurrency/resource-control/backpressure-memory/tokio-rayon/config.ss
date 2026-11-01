;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Pure configuration of the selected specialization Library.
(import :clan/poo/object "objects.ss")
(export Config)
(def Config
  (.o
    purpose: 'tokio-rayon-authored-model
    coding-policy: BackpressureCodingPolicy
    design-policy: BackpressureDesignPolicy
    catalog: OwnershipCatalog
    mapping: TraceMapping
    cases: integration-case-definitions))
