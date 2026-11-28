;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Declarative sealed Record contracts for .qnt-SSOT models, profiles and plans (10.204).
;;; No Scheme-side Quint AST duplication (state/guards/transitions/safety/traces/countermodels)
;;; is permitted: sealed: #t mechanically rejects any such slot with TypeError.
(import
  :clan/poo/object
  (only-in :clan/poo/type define-type Any Object Function Type Type. Bool
           Record Symbol String List Exactly Or element?)
  (only-in :deterministic-engineering/types LibraryNonemptyString))
(export QuintTimeout QuintDepth QuintSeed QuintStepKind QuintExpectedExit
        QuintRuleRow QuintDepRow
        QuintDomainModelShape QuintDomainModelType
        ThreatDomainModelType EngineeringDomainModelType
        EngineeringCatalogConfigContract ThreatCatalogConfigContract
        QuintCheckStep QuintPolicyType QuintProfileType QuintPlanType
        QuintGuardClassification QuintGuardAuditEntryType QuintGuardAuditReportType
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

(define-type (QuintDepth @ Type.)
  identity: 'quint/depth
  .element?: (lambda (v) (and (exact-integer? v) (>= v 1) (<= v 64))))

;; Hard sealed .qnt-SSOT metadata contract (10.204).
;; Any attempt to embed state:, guards:, transitions:, safety:, traces:, countermodels:,
;; parameters:, quint-imports:, verify-depth:, or countermodel-depth: in Scheme fails with TypeError.
(define-type
  (QuintDomainModelShape @
   (Record identity: [Symbol]
           family: [Symbol]
           title: [LibraryNonemptyString optional: #t]
           subdomain: [Symbol optional: #t]
           papers: [(List Any) optional: #t]
           parent: [Any optional: #t]
           revision: [LibraryNonemptyString optional: #t]
           factor-implications: [(List Any) optional: #t]
           quint-module: [LibraryNonemptyString]
           quint-file: [LibraryNonemptyString]
           domain-dir: [LibraryNonemptyString]
           rules: [(List QuintRuleRow)]
           dependencies: [(List QuintDepRow)]
           invariant: [LibraryNonemptyString]
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
               (string-starts-with? dir "engineering/"))))))

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
         (string-starts-with? (.get m domain-dir) "engineering/"))))

;; Shared sealed catalog entry contracts (10.205): eliminates 95 identical per-model types.ss files.
(define-type
  (EngineeringCatalogConfigContract @
   (Record entry: [EngineeringDomainModelType]))
  sealed: #t)

(define-type
  (ThreatCatalogConfigContract @
   (Record entry: [ThreatDomainModelType]))
  sealed: #t)

(define-type (QuintTimeout @ Type.)
  identity: 'quint/timeout
  .element?: (lambda (v) (and (exact-integer? v) (>= v 1) (<= v 120))))

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

(define-type QuintGuardClassification
  (Or (Exactly 'essential)
      (Exactly 'precondition)
      (Exactly 'redundant)
      (Exactly 'under-modeled)
      (Exactly 'unwitnessed)))

(define-type
  (QuintGuardAuditEntryType @
   (Record guard-id: [Symbol]
           classification: [QuintGuardClassification]
           in-ast?: [Bool]
           witnessed?: [Bool]
           witness: [LibraryNonemptyString optional: #t]
           rationale: [LibraryNonemptyString optional: #t]))
  sealed: #t)

(define-type
  (QuintGuardAuditReportType @
   (Record model-identity: [Symbol]
           declared-guards: [(List Symbol)]
           ast-guards: [(List Symbol)]
           witnessed-guards: [(List Symbol)]
           unwitnessed-guards: [(List Symbol)]
           undeclared-ast-guards: [(List Symbol)]
           entries: [(List QuintGuardAuditEntryType)]
           passed?: [Bool]))
  sealed: #t)

(define-type
  (QuintMethodsContractsShape @
   (Record policy: [Type]
           plan: [Type]
           profile: [Type]
           step: [Type]
           guard-audit: [Type]
           scope: [Type]))
  sealed: #t)

(define-type QuintMethodsScopeType
  (.cc
    (Record config: [QuintPolicyType]
            config-type: [Type]
            parse-spec: [(Function (list LibraryNonemptyString) (list Object))]
            project-readme: [(Function (list Object LibraryNonemptyString) (list LibraryNonemptyString))]
            plan: [(Function (list Object LibraryNonemptyString QuintProfileType QuintPolicyType) (list QuintPlanType))]
            audit-guards: [(Function (list Object LibraryNonemptyString) (list QuintGuardAuditReportType))]
            contracts: [QuintMethodsContractsShape])
    'identity 'quint-methods/scope))
