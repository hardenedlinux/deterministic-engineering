;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Sealed contracts for G1-G4 Defensive Governance:
;;;   - G1 Five-Tuple Guard Admission Contract
;;;   - G2 AI Agent Defensive-Hallucination Controls
;;;   - G4 Proportional Review Tiers
;;; Pure declarations; zero I/O or process launch.
(import :clan/poo/object
        (only-in :clan/poo/type define-type Any Object Type Symbol Bool List Or Exactly Record)
        (only-in :deterministic-engineering/types LibraryNonemptyString)
        (only-in :deterministic-engineering/library/defensive-boundaries/types
                 DefensivePathologyType PremiseMutabilityType))
(export GuardWitnessKindType
        GuardAdmissionFiveTupleType
        AgentHallucinationClassType
        AgentHallucinationControlType
        ReviewTierType
        DefensiveGovernanceScopeType)

(define-type GuardWitnessKindType
  (Or (Exactly 'apalache-countermodel)
      (Exactly 'cbmc-proof)
      (Exactly 'mbt-counterexample)
      (Exactly 'typed-precondition)))

(define-type
  (GuardAdmissionFiveTupleType @
   (Record guard-id: [Symbol]
           obligation: [LibraryNonemptyString]
           owner: [Symbol]
           scoped-failure: [LibraryNonemptyString]
           witness-kind: [GuardWitnessKindType]
           witness-ref: [LibraryNonemptyString]
           affected-consumer: [Symbol]
           mutability: [PremiseMutabilityType]
           pathology-prevented: [DefensivePathologyType]
           claims-immutable-reuse?: [Bool]))
  sealed: #t)

(define-type AgentHallucinationClassType
  (Or (Exactly 'silent-fallback)
      (Exactly 'floor-weakening)
      (Exactly 'redundant-defensive-glue)
      (Exactly 'fabricated-evidence)))

(define-type
  (AgentHallucinationControlType @
   (Record identity: [Symbol]
           hallucination-class: [AgentHallucinationClassType]
           symptom: [LibraryNonemptyString]
           mechanical-refusal: [LibraryNonemptyString]
           governing-contract: [Symbol]))
  sealed: #t)

(define-type ReviewTierType
  (Or (Exactly 'mechanical-syntax)
      (Exactly 'bounded-contract)
      (Exactly 'semantic-review)))

(define-type DefensiveGovernanceScopeType
  (.cc
    (Record admit-guard: [Any]
            audit-submission: [Any]
            audit-scheme-datums: [Any]
            hallucination-controls: [(List AgentHallucinationControlType)]
            revalidation-program: [Any]
            reason-revalidation: [Any]
            contracts: [Object])
    'identity 'defensive-governance/scope))
