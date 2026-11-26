;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Sealed contracts for G3/G4 Orthogonal Defense Profiles (10.153 / Yuanxu Design 165).
(import :clan/poo/object
        (only-in :clan/poo/type define-type Object List Any Record))
(export DefenseProfilesScopeType)

(define-type DefenseProfilesScopeType
  (.cc
    (Record slot-specs: [(List Any)]
            default-slots: [Object]
            governance-floor: [Object]
            profiles: [Object]
            registry: [Object]
            converge: [Any]
            apply-runtime: [Any])
    'identity 'defense-profiles/scope))
