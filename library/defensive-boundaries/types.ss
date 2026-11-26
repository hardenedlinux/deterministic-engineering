;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Sealed Record contracts for C1-C3 Defensive Programming Anti-Pattern Catalog,
;;; Deterministic Boundary Replacements, and Mechanical vs. Semantic Check Split (10.153).
;;; Pure declarations; zero I/O or process execution.
(import :clan/poo/object
        (only-in :clan/poo/type define-type Any Object Type Symbol List Or Exactly Record)
        (only-in :deterministic-engineering/types LibraryNonemptyString))
(export DefensivePathologyType
        PremiseMutabilityType
        CheckEnforcementKindType
        AntiPatternEntryType
        ContrastSubjectType
        DefensiveBoundariesScopeType)

(define-type DefensivePathologyType
  (Or (Exactly 'P1-masking)
      (Exactly 'P2-misplaced)
      (Exactly 'P3-over-blocking)
      (Exactly 'P4-bloat)))

(define-type PremiseMutabilityType
  (Or (Exactly 'M1-immutable)
      (Exactly 'M2-negative-domain)
      (Exactly 'M3-mutable-root)))

(define-type CheckEnforcementKindType
  (Or (Exactly 'mechanical-type)
      (Exactly 'mechanical-formal)
      (Exactly 'mechanical-mbt)
      (Exactly 'semantic-review)))

(define-type
  (AntiPatternEntryType @
   (Record identity: [Symbol]
           pathology: [DefensivePathologyType]
           mutability: [PremiseMutabilityType]
           anti-pattern: [LibraryNonemptyString]
           deterministic-replacement: [LibraryNonemptyString]
           enforcement-kinds: [(List CheckEnforcementKindType)]
           quint-model-ref: [Symbol optional: #t]
           contrast-subject-ref: [LibraryNonemptyString optional: #t]))
  sealed: #t)

(define-type
  (ContrastSubjectType @
   (Record identity: [Symbol]
           language: [(Or (Exactly 'ts) (Exactly 'c) (Exactly 'cpp) (Exactly 'rust))]
           relative-dir: [LibraryNonemptyString]
           pathologies-covered: [(List DefensivePathologyType)]
           verification-tool: [LibraryNonemptyString]))
  sealed: #t)

(define-type DefensiveBoundariesScopeType
  (.cc
    (Record catalog: [(List AntiPatternEntryType)]
            contrast-subjects: [(List ContrastSubjectType)]
            lookup-by-pathology: [Any]
            contracts: [Object])
    'identity 'defensive-boundaries/scope))
