;;; Public value contracts describe inputs and plans; none grants execution rights.
(import
  :clan/poo/object
  (only-in :clan/poo/mop define-type Any Object Function Type Bool)
  (only-in :clan/poo/type Record Symbol String List Exactly Or)
  (only-in "../../types.ss" LibraryNonemptyString))
(export SourceContractProfile SourceContractTools SourceContractPlan
        SourceContractPolicyShape SourceContractScopeType)

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

(define-type SourceContractScopeType
  (.cc
    (Record config: [SourceContractPolicyShape]
            config-type: [Type]
            strategies: [Object]
            plan: [(Function (list SourceContractPlan)
                             (list Object SourceContractProfile))]
            contracts: [Object])
    'identity 'source-contracts/scope))
