;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Declarative sealed Record contracts for Quint projection, profiles and plans.
;;; No process launch, filesystem access or execution authority belongs here.
(import
  :clan/poo/object
  (only-in :clan/poo/type define-type Any Object Function Type Type. Bool
           Record Symbol String List Exactly Or element?)
  (only-in "../../types.ss" LibraryNonemptyString))
(export QuintTimeout QuintDepth QuintSeed QuintStepKind QuintExpectedExit
        QuintCheckStep QuintPolicyType QuintProfileType QuintPlanType
        QuintMethodsContractsShape QuintMethodsScopeType)

(define-type (QuintTimeout @ Type.)
  identity: 'quint/timeout
  .element?: (lambda (v) (and (exact-integer? v) (>= v 1) (<= v 120))))

(define-type (QuintDepth @ Type.)
  identity: 'quint/depth
  .element?: (lambda (v) (and (exact-integer? v) (>= v 1) (<= v 64))))

(define-type (QuintSeed @ Type.)
  identity: 'quint/seed
  .element?: (lambda (v) (and (exact-integer? v) (>= v 1))))

(define-type QuintStepKind
  (Or (Exactly "typecheck")
      (Exactly "deterministic-traces")
      (Exactly "bounded-safety")
      (Exactly "required-countermodel")))

(define-type QuintExpectedExit
  (Or (Exactly 0) (Exactly 1)))

(define-type
  (QuintCheckStepShape @
   (Record label: [LibraryNonemptyString]
           command: [(List LibraryNonemptyString)]
           expected-exit: [QuintExpectedExit]
           kind: [QuintStepKind]
           dropped-guard: [LibraryNonemptyString optional: #t]
           expected-itf-predicate: [LibraryNonemptyString optional: #t]))
  sealed: #t)

(define-type (QuintCheckStep @ QuintCheckStepShape)
  identity: 'quint/check-step
  .element?:
  (lambda (step)
    (and (element? QuintCheckStepShape step)
         (let ((kind (.get step kind))
               (exit-code (.get step expected-exit)))
           (cond
            ((equal? kind "required-countermodel")
             (and (= exit-code 1)
                  (.slot? step 'dropped-guard)
                  (.slot? step 'expected-itf-predicate)))
            (else (= exit-code 0)))))))

(define-type
  (QuintPolicyType @
   (Record quint-version: [LibraryNonemptyString]
           apalache-version: [LibraryNonemptyString]
           timeout: [QuintTimeout]))
  sealed: #t)

(define-type
  (QuintProfileType @
   (Record identity: [Symbol]
           model: [Object]
           seed: [QuintSeed]
           positive-depth: [QuintDepth]
           negative-depth: [QuintDepth]
           require-countermodels?: [Bool]))
  sealed: #t)

(define-type
  (QuintPlanShape @
   (Record module: [LibraryNonemptyString]
           file: [LibraryNonemptyString]
           quint-version: [LibraryNonemptyString]
           apalache-version: [LibraryNonemptyString]
           seed: [QuintSeed]
           positive-depth: [QuintDepth]
           negative-depth: [QuintDepth]
           timeout: [QuintTimeout]
           steps: [(List QuintCheckStep)]))
  sealed: #t)

(define-type (QuintPlanType @ QuintPlanShape)
  identity: 'quint/plan
  .element?:
  (lambda (plan)
    (and (element? QuintPlanShape plan)
         (let ((steps (.get plan steps)))
           (and (pair? steps)
                (and (find (lambda (s) (equal? (.get s kind) "typecheck")) steps) #t))))))

(define-type
  (QuintMethodsContractsShape @
   (Record policy: [Type]
           plan: [Type]
           profile: [Type]
           step: [Type]
           scope: [Type]))
  sealed: #t)

(define-type QuintMethodsScopeType
  (.cc
    (Record config: [QuintPolicyType]
            config-type: [Type]
            project-module: [(Function (list Object) (list LibraryNonemptyString))]
            plan: [(Function (list Object QuintProfileType QuintPolicyType) (list QuintPlanType))]
            contracts: [QuintMethodsContractsShape])
    'identity 'quint-methods/scope))
