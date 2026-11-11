;;; Tool method declarations; authored domain meaning lives in the Library.
(import :clan/poo/object "types.ss"
  "../backpressure-tokio-rayon/objects.ss"
  (only-in "../backpressure-memory/types.ss" BackpressureDeclarationContract))
(export RustMethodDefinitions method-ref)
;; Each operation has an authored contract and complete required input classes.
;; Capturing those classes and their actual origins is a later operation boundary.
(.def ResourceMethod.
  operation: (error "Resource method requires an explicit operation")
  identity: (string->symbol (string-append "rust.resources." (symbol->string operation)))
  revision: "resource-method-declaration/v1"
  owner: 'rust-resources
  role: 'method
  family: 'concurrency.resource-control.backpressure-memory
  declaration-contract: BackpressureDeclarationContract
  contract: ResourceMethodDefinitionContract
  provider: 'rust-resources
  result-owner: 'rust-resources
  ;; The effective operation selects published requirements. Descendants can
  ;; refine their values; the admission Contract checks against the original.
  kind: (.get (.ref ResourceMethodRequirements operation) kind)
  strength: (.get (.ref ResourceMethodRequirements operation) strength)
  signature: (.get (.ref ResourceMethodRequirements operation) signature)
  modes: (.get (.ref ResourceMethodRequirements operation) modes)
  input-demands: (.get (.ref ResourceMethodRequirements operation) inputs)
  policy-ids: '(rust.resources.backpressure-memory.review-policy
                rust.resources.backpressure-memory.design-review-policy)
  result-kinds: '(observation counterevidence)
  premises: (list
             (.o
               identity: 'complete-method-basis
               inputs: input-demands
               statement: "Execution must bind every declared input class, its actual source, tool/runtime dependencies and applicability."))
  limits: (list
           (.o
             identity: 'method-strength
             inputs: input-demands
             statement: "A completed command or local result is not C, authorization, universal refinement or an accepted current-use view."))
  program-ref: #f
  catalog-ref: #f
  mapping-ref: #f)
(.def ResourceMethodAsset.
  revision: "resource-method-declaration/v1"
  owner: 'rust-resources)
(.def (MethodObserverAsset @ ResourceMethodAsset.)
  identity: 'observer
  kind: 'scheme
  relative-path: "objects.ss")
(def RustMethodDefinitions
  (.o
    native: (.o (:: @ ResourceMethod.)
                operation: 'native
                model-ids: '(rust.resources.backpressure-memory)
                claims: (map (lambda (case-value) (car (.get case-value obligations))) integration-case-definitions)
                assets: (list
                         (.o (:: @ ResourceMethodAsset.)
                             identity: 'native-subject
                             owner: 'rust-resource-lifecycle
                             kind: 'rust
                             relative-path: "../../languages-engineering/rust/concurrency/resource-control/backpressure-memory/src/main.rs")
                         MethodObserverAsset
                         (.o (:: @ ResourceMethodAsset.)
                             identity: 'oracle
                             kind: 'scheme
                             relative-path: "oracle.ss")))
    quint: (.o (:: @ ResourceMethod.)
               operation: 'quint
               model-ids: '(concurrency.resource-control.backpressure-memory rust.resources.backpressure-memory)
               claims: '(BP-O02)
               assets: (list
                        (.o (:: @ ResourceMethodAsset.)
                            identity: 'ownership-model
                            owner: 'backpressure-memory
                            kind: 'quint
                            relative-path: "../backpressure-memory/model.qnt")
                        MethodObserverAsset))
    lean: (.o (:: @ ResourceMethod.)
              operation: 'lean
              model-ids: '(concurrency.resource-control.backpressure-memory rust.resources.backpressure-memory)
              claims: '(BP-O03)
              assets: (list
                       (.o (:: @ ResourceMethodAsset.)
                           identity: 'budget-proof
                           owner: 'backpressure-memory
                           kind: 'lean
                           relative-path: "../backpressure-memory/budget.lean")
                       MethodObserverAsset))
    integration: (.o (:: @ ResourceMethod.)
                     operation: 'integration
                     model-ids: '(rust.resources.backpressure-memory.integration)
                     claims: (apply
                              append
                              (map (lambda (case-value) (cdr (.get case-value obligations))) integration-case-definitions))
                     assets: (list
                              (.o (:: @ ResourceMethodAsset.)
                                  identity: 'correspondence
                                  kind: 'scheme
                                  relative-path: "correspondence.ss")
                              (.get OwnershipCatalog asset))
                     catalog-ref: (method-ref OwnershipCatalog)
                     mapping-ref: (method-ref TraceMapping))))

(def (method-ref definition-value)
  (.o
    identity: (.get definition-value identity)
    revision: (.get definition-value revision)
    owner: (.get definition-value owner)))
