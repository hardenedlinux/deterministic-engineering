;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Public value contracts describe inputs and plans; none grants execution rights.
(import
  :clan/poo/object
  (only-in :clan/poo/mop define-type Any Object Function Type Bool)
  (only-in :clan/poo/type Record Symbol String List Exactly Or)
  (only-in "../../types.ss" LibraryNonemptyString LibraryRuleCatalogShape))
(export SourceContractProfile SourceContractTools SourceContractPlan
        SourceContractPolicyShape SourceContractConfig SourceContractScopeType SourceContractScenario)

(define-type
  (SourceLanguage @
   (Record identity: [Symbol]
           compiler-key: [Symbol]
           native-standard: [LibraryNonemptyString]
           verifier-flags: [(List LibraryNonemptyString)]))
  sealed: #t)

(define-type
  (SourceExecutor @
   (Record identity: [Symbol]
           method: [Symbol]
           requires-properties?: [Bool]))
  sealed: #t)

(define-type
  (SourceInstrumentation @
   (Record identity: [Symbol]
           option: [String]
           requires-function?: [Bool]))
  sealed: #t)

(define-type
  (SourceContractProfile @
   (Record identity: [Symbol]
           language: [SourceLanguage]
           executor: [SourceExecutor]
           obligation: [Symbol]
           factor: [Symbol]
           method: [Symbol]
           function: [LibraryNonemptyString]
           enforce: [String]
           instrumentation: [SourceInstrumentation]
           units: [(List LibraryNonemptyString)]
           inputs: [(List LibraryNonemptyString)]
           expected-properties: [(List LibraryNonemptyString)]))
  sealed: #t)

;; Pure finite binding checks belong to the Library, not an execution adapter.
(def (scenario-binding-diagnostics value location)
  (def profile (.get value profile))
  (def entry (.get value entry))
  (filter-map
    (lambda (check)
      (and (not (cdr check)) (.o kind: (car check) path: location)))
    (list
      (cons 'scenario/method-agreement
        (eq? (.get profile method) (.get profile executor method)))
      (cons 'scenario/instrumentation-boundary
        (eq? (.get profile instrumentation requires-function?)
             (not (string=? (.get profile enforce) ""))))
      (cons 'scenario/catalog-obligation
        (member (list (.get profile factor) (.get profile obligation) (.get profile method))
                (.get entry rules)))
      (cons 'scenario/nonempty-capture
        (and (pair? (.get profile units)) (pair? (.get profile inputs))
             (or (not (.get profile executor requires-properties?))
                 (pair? (.get profile expected-properties)))))
      (cons 'scenario/unit-closure
        (andmap (lambda (unit) (member unit (.get profile inputs)))
                (.get profile units))))))

(define-type
  (SourceContractScenario @
   (Record root: [LibraryNonemptyString]
           entry: [LibraryRuleCatalogShape]
           profile: [SourceContractProfile]))
  .element?: =>
  (lambda (inherited)
    (lambda (value)
      (and (inherited value) (null? (scenario-binding-diagnostics value '())))))
  sealed: #t)

;; Tool locations are an external consumer's input contract, not discovered here.
(define-type
  (SourceContractTools @
   (Record cbmc: [LibraryNonemptyString]
           goto-cc: [LibraryNonemptyString]
           goto-instrument: [LibraryNonemptyString]
           cc: [LibraryNonemptyString]
           cxx: [LibraryNonemptyString]))
  sealed: #t)

(define-type
  (VerificationStep @
   (Record tool: [Symbol]
           arguments: [(List (Or String Symbol))]
           expected: [(Or (Exactly 'zero) (Exactly 'solver))]
           artifacts: [(List Symbol)]))
  sealed: #t)

(define-type
  (SourceContractPlan @
   (Record kind: [(Exactly 'verification-plan)]
           obligation: [Symbol]
           method: [Symbol]
           steps: [(List VerificationStep)]
           external-tools: [(List Symbol)]
           expected-properties: [(List LibraryNonemptyString)]
           boundary: [LibraryNonemptyString]))
  sealed: #t)

(define-type
  (SourceContractPolicyShape @
   (Record timeout: [(Exactly 45)]
           safety-flags:
           [(Exactly '("--bounds-check" "--pointer-check"
                        "--signed-overflow-check" "--unsigned-overflow-check"
                        "--unwinding-assertions" "--unwind" "8"))]))
  sealed: #t)

(define-type
  (SourceContractConfig @
   (Record enable: [Bool]
           settings: [SourceContractPolicyShape]))
  sealed: #t)

(define-type SourceContractScopeType
  (.cc
    (Record config: [SourceContractConfig]
            config-type: [Type]
            strategies: [Object]
            scenario: [Object]
            plan: [(Function (list SourceContractPlan)
                             (list Object SourceContractProfile))]
            contracts: [Object])
    'identity 'source-contracts/scope))
