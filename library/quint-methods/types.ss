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
        QuintImportRow QuintParamRow QuintStateField QuintGuardRow
        QuintTransitionRow QuintTraceRow QuintRuleRow QuintDepRow
        QuintCountermodelType QuintDomainModelShape QuintDomainModelType
        ThreatDomainModelType EngineeringDomainModelType
        QuintCheckStep QuintPolicyType QuintProfileType QuintPlanType
        QuintMethodsContractsShape QuintMethodsScopeType)

(def (list-tuple-type id . elem-types)
  (define-type (RowType @ Type.)
    identity: id
    .element?:
    (lambda (v)
      (and (list? v)
           (= (length v) (length elem-types))
           (let loop ((xs v) (ts elem-types))
             (or (null? xs)
                 (and (element? (car ts) (car xs))
                      (loop (cdr xs) (cdr ts))))))))
  RowType)

(def QuintImportRow (list-tuple-type 'quint/import-row LibraryNonemptyString LibraryNonemptyString))
(def QuintParamRow (list-tuple-type 'quint/param-row Symbol LibraryNonemptyString))
(def QuintStateField
  (Or (list-tuple-type 'quint/state-field-init Symbol LibraryNonemptyString LibraryNonemptyString)
      (list-tuple-type 'quint/state-field-pure Symbol LibraryNonemptyString)))
(def QuintGuardRow (list-tuple-type 'quint/guard-row Symbol LibraryNonemptyString))
(def QuintTransitionRow (list-tuple-type 'quint/transition-row Symbol LibraryNonemptyString))
(def QuintTraceRow (list-tuple-type 'quint/trace-row Symbol LibraryNonemptyString))
(def QuintRuleRow (list-tuple-type 'quint/rule-row Symbol Symbol (Exactly 'quint)))
(def QuintDepRow
  (list-tuple-type 'quint/dep-row Symbol (Or (Exactly 'source) (Exactly 'profile) (Exactly 'method))))

(def (string-starts-with? s prefix)
  (and (string? s)
       (>= (string-length s) (string-length prefix))
       (equal? (substring s 0 (string-length prefix)) prefix)))

(def (string-ends-with? s suffix)
  (and (string? s)
       (>= (string-length s) (string-length suffix))
       (equal? (substring s (- (string-length s) (string-length suffix)) (string-length s)) suffix)))

(define-type
  (QuintCountermodelType @
   (Record identity: [Symbol]
           dropped-guard: [Symbol]
           step-action: [LibraryNonemptyString]
           counter-action: [LibraryNonemptyString]
           expected-itf-predicate: [LibraryNonemptyString]))
  sealed: #f)

(define-type
  (QuintDomainModelShape @
   (Record identity: [Symbol]
           family: [Symbol]
           parent: [Any optional: #t]
           revision: [LibraryNonemptyString optional: #t]
           factor-implications: [(List Any) optional: #t]
           quint-module: [LibraryNonemptyString]
           quint-file: [LibraryNonemptyString]
           domain-dir: [LibraryNonemptyString]
           quint-imports: [(List QuintImportRow) optional: #t]
           rules: [(List QuintRuleRow)]
           dependencies: [(List QuintDepRow)]
           invariant: [LibraryNonemptyString]
           parameters: [(List QuintParamRow)]
           state: [(List QuintStateField)]
           guards: [(List QuintGuardRow)]
           transitions: [(List QuintTransitionRow)]
           safety: [LibraryNonemptyString]
           traces: [(List QuintTraceRow)]
           countermodels: [(List QuintCountermodelType)]
           limits: [LibraryNonemptyString]))
  sealed: #t)

(define-type (QuintDomainModelType @ QuintDomainModelShape)
  identity: 'quint/domain-model
  .element?:
  (lambda (m)
    (and (element? QuintDomainModelShape m)
         (string-ends-with? (.get m quint-file) ".qnt")
         (let ((dir (.get m domain-dir)))
           (or (string-starts-with? dir "threat/")
               (string-starts-with? dir "engineering/")))
         ;; Every countermodel's dropped-guard must reference a declared guard of the model.
         (let ((guard-ids (map car (.get m guards))))
           (andmap (lambda (cm) (and (memq (.get cm dropped-guard) guard-ids) #t))
                   (.get m countermodels)))
         ;; Stateful models (3-tuple state fields) must declare a 'step transition.
         (let ((st (.get m state)))
           (or (null? st)
               (not (= (length (car st)) 3))
               (and (assq 'step (.get m transitions)) #t))))))

(define-type (ThreatDomainModelType @ QuintDomainModelType)
  identity: 'quint/threat-domain-model
  .element?:
  (lambda (m)
    (and (element? QuintDomainModelType m)
         (string-starts-with? (.get m domain-dir) "threat/"))))

(define-type (EngineeringDomainModelType @ QuintDomainModelType)
  identity: 'quint/engineering-domain-model
  .element?:
  (lambda (m)
    (and (element? QuintDomainModelType m)
         (string-starts-with? (.get m domain-dir) "engineering/")
         (pair? (.get m countermodels)))))

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
           model: [QuintDomainModelType]
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
