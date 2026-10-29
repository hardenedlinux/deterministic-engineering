;;; -*- Gerbil -*-
(import
  :clan/poo/object
  "types.ss"
  (only-in "../abstract/types.ss" BackpressureDeclarationContract))
(export
  RustMethodDefinitions
  specialize-backpressure
  make-backpressure-integration
  BackpressureCodingPolicy
  BackpressureDesignPolicy)
(def (specialize-backpressure BackpressureModel)
  (.o (:: @ BackpressureModel)
      identity: 'rust.resources.backpressure-memory
      revision: "backpressure/v3"
      role: 'specialization
      contract: RustResourceModelContract
      parent: BackpressureModel
      design: "10.17"
      trajectories: '("10.10" "10.11" "10.15")
      lifecycle: '(waiting queued cpu-running result-pending cleanup released)
      state-map: '((waiting waiting)
                   (queued queued)
                   (cpu-running active)
                   (result-pending returned)
                   (cleanup cleanup)
                   (released released))
      rules: => (cut
                 append
                 <>
                 '(
                   (bounded-retention BP-O04 review)
                   (bounded-retention BP-O07 native)
                   (tokio TR-O01 native)
                   (rayon TR-O02 review)
                   (async-cpu-handoff TR-O03 quint)
                   (cache CA-O01 native)
                   (retry BP-O05 quint))
                 (map
                  (lambda (case-value) (list (.get case-value factor) (car (.get case-value obligations)) 'native))
                  integration-case-definitions))
      dependencies: => (cut
                        append
                        <>
                        (append
                         '((BP-O04 model)
                           (BP-O04 source)
                           (BP-O04 runtime)
                           (BP-O07 workload)
                           (BP-O07 source)
                           (BP-O07 runtime)
                           (TR-O01 runtime)
                           (TR-O01 source)
                           (TR-O01 workload)
                           (TR-O02 runtime)
                           (TR-O02 source)
                           (TR-O02 model)
                           (TR-O03 model)
                           (TR-O03 runtime)
                           (CA-O01 cache)
                           (CA-O01 source)
                           (CA-O01 workload)
                           (BP-O05 model)
                           (BP-O05 runtime))
                         (apply
                          append
                          (map
                           (lambda (case-value)
                             (map (cut list (car (.get case-value obligations)) <>) '(source runtime workload inventory)))
                           integration-case-definitions))))
      method-refs: (map (lambda (key) (method-ref (.ref RustMethodDefinitions key))) '(native quint lean))
      qualification: 'authored-specialization))

;; One authored inventory and one typed transition/delta meaning.
(def common-labels '("payload-created" "payload-dropped" "held" "final"))
(def worker-labels '("cpu-started" "started" "cpu-released" "cpu-finished"))
(.def IntegrationCase.
  name: (error "Integration case requires a name")
  obligations: (map (lambda (prefix) (string->symbol (string-append prefix name))) '("RL-" "SI-" "TM-"))
  labels: (append common-labels (if (equal? name "M02") '() worker-labels)))
(def integration-case-definitions
  (list
   (.o (:: @ IntegrationCase.)
       name: "M01"
       factor: 'normal-handoff
       labels: => (cut append <> '("returned")))
   (.o (:: @ IntegrationCase.)
       name: "M02"
       factor: 'admission-cancellation
       labels: => (cut append <> '("waiter-pending" "waiter-cancelled")))
   (.o (:: @ IntegrationCase.)
       name: "M03"
       factor: 'abandoned-result
       labels: => (cut append <> '("receiver-dropped" "delivery-failed-retained")))
   (.o (:: @ IntegrationCase.)
       name: "M04"
       factor: 'caller-abort
       labels: => (cut append <> '("caller-waiting" "caller-cancelled" "delivery-failed-retained")))
   (.o (:: @ IntegrationCase.)
       name: "M05"
       factor: 'cleanup-full
       labels: => (cut append <> '("cleanup-full-retained")))
   (.o (:: @ IntegrationCase.)
       name: "M06"
       factor: 'caller-owned-permit
       labels: => (cut append <> '("caller-waiting" "caller-cancelled" "delivery-failed-retained")))))
(def integration-native-keys '(source runtime workload inventory))
(.def OwnershipTransition.
  cases: '()
  reservation: 'keep)
(.def OwnershipCatalog
  identity: 'backpressure.ownership-catalog
  revision: "observed-ownership-constraint"
  owner: 'rust-resources
  role: 'catalog
  family: 'concurrency.resource-control.backpressure-memory
  declaration-contract: BackpressureDeclarationContract
  contract: BackpressureOwnershipCatalogContract
  parent: #f
  asset: (.o
           identity: 'ownership-notation
           revision: "observed-ownership-constraint"
           owner: 'rust-resources
           kind: 'sysml
           relative-path: "ownership.sysml")
  package: 'BackpressureOwnership
  definition: 'Ownership
  attributes: '(live reserved)
  live-attribute: 'live
  reservation-attribute: 'reserved
  constraint: 'retainedRequiresReservation
  references: '(ScalarValues))
(.def TraceMapping
  identity: 'backpressure.observed-cuts
  revision: "single-job-observed-cuts/v1"
  owner: 'rust-resources
  role: 'mapping
  family: 'concurrency.resource-control.backpressure-memory
  declaration-contract: BackpressureDeclarationContract
  contract: BackpressureTraceMappingContract
  parent: #f
  catalog-id: (.get OwnershipCatalog identity)
  cases: integration-case-definitions
  initial: 'waiting
  final: 'done
  cut-labels: '("started" "held" "returned" "final")
  qnt-stages: '(queued running returned cleanup done)
  qnt-fields: '(limit queueLimit admitted queued running returned cleanup done)
  qnt-initializer: 'initResource
  qnt-step: 'step
  delta: (.o
           identity: 'cancelQueued
           from: 'queued
           to: 'cleanup
           subject: 0
           frame: '(limit queueLimit admitted running returned done))
  transitions: (list
                (.o (:: @ OwnershipTransition.)
                    event: "payload-created"
                    from: '(waiting)
                    to: 'queued
                    reservation: 'reserve)
                (.o (:: @ OwnershipTransition.)
                    event: "cpu-started"
                    from: '(queued)
                    to: 'running)
                (.o (:: @ OwnershipTransition.)
                    event: "delivery-failed-retained"
                    from: '(running)
                    to: 'cleanup)
                (.o (:: @ OwnershipTransition.)
                    event: "cleanup-full-retained"
                    from: '(running)
                    to: 'cleanup)
                (.o (:: @ OwnershipTransition.)
                    event: "returned"
                    from: '(running)
                    to: 'returned)
                (.o (:: @ OwnershipTransition.)
                    event: "payload-dropped"
                    cases: '("M02")
                    from: '(queued)
                    to: 'cleanup)
                (.o (:: @ OwnershipTransition.)
                    event: "caller-cancelled"
                    cases: '("M06")
                    from: '()
                    to: 'unchanged
                    reservation: 'release)
                (.o (:: @ OwnershipTransition.)
                    event: "final"
                    from: '(cleanup returned)
                    to: 'done
                    reservation: 'release))
  loss: "Observed single-job cuts; queued cancellation extends the base model; not complete Rust refinement")
(def (make-backpressure-integration parent-model)
  (.o (:: @ parent-model)
      role: 'integration
      contract: BackpressureIntegrationContract
      parent: parent-model
      method-refs: => (cut append <> (list (method-ref (.get RustMethodDefinitions integration))))
      identity: 'rust.resources.backpressure-memory.integration
      revision: "backpressure-integration/v1"
      mapping: TraceMapping
      catalog: OwnershipCatalog
      case-links: (map (cut .get <> obligations) (.get mapping cases))
      rules: => (cut
                 append
                 <>
                 (apply
                  append
                  (map
                   (lambda (case-value)
                     (list
                      (list (.get case-value factor) (cadr (.get case-value obligations)) 'sysml)
                      (list (.get case-value factor) (caddr (.get case-value obligations)) 'correspondence)))
                   (.get mapping cases))))
      dependencies: => (cut
                        append
                        <>
                        (apply
                         append
                         (map
                          (lambda (case-value)
                            (append
                             (map
                              (cut list (cadr (.get case-value obligations)) <>)
                              (append integration-native-keys '(correspondence sysml-tool)))
                             (map
                              (cut list (caddr (.get case-value obligations)) <>)
                              (append integration-native-keys '(correspondence quint-tool)))))
                          (.get mapping cases))))))

;; Two independent authored policies. Neither appoints principals or grants use.
(.def BackpressureCodingPolicy
  identity: 'rust.resources.backpressure-memory.review-policy
  role: 'policy
  family: 'concurrency.resource-control.backpressure-memory
  declaration-contract: BackpressureDeclarationContract
  contract: BackpressureReviewPolicyContract
  parent: #f
  revision: "controlled-ownership-coding-review"
  model-ids: '(rust.resources.backpressure-memory)
  slice-ids: '(rust.resources.backpressure-memory.integration)
  criteria: (list
             (.o
               identity: 'worker-owned-lifecycle
               meaning: "Review the five worker-owned permit paths under the selected controlled execution profile."
               duties: '(RL-M01 RL-M02 RL-M03 RL-M04 RL-M05)
               inputs: '(source runtime workload inventory)
               negative-controls: '(caller-owned-permit unbound-tool changed-input)
               strength: 'execution)
             (.o
               identity: 'bounded-formal-correspondence
               meaning: "Keep finite-model, arithmetic and observed-cut correspondence conclusions distinct."
               duties: '(BP-O02 BP-O03)
               inputs: '(model arithmetic correspondence)
               negative-controls: '(early-release unsupported-delta missing-cut)
               strength: 'authored-conditional))
  required-products: '(source-inventory method-results counterevidence)
  required-roles: '(implementation-owner independent-reviewer)
  conditions: (list
               (.o
                 identity: 'coding-applicability
                 inputs: '(source workload)
                 statement: "The policy applies to the declared controlled worker-owned mechanism and preserves the caller-owned counterexample as investigation evidence.")
               (.o
                 identity: 'coding-currentness
                 inputs: '(source runtime inventory)
                 statement: "Missing, conflicting, stale or weaker evidence remains visible; matching labels and historical successes cannot satisfy current duties."))
  limitations: '("Controlled suite qualification is not a production throughput claim or institutional classification."))
(.def BackpressureDesignPolicy
  identity: 'rust.resources.backpressure-memory.design-review-policy
  role: 'policy
  family: 'concurrency.resource-control.backpressure-memory
  declaration-contract: BackpressureDeclarationContract
  contract: BackpressureDesignReviewPolicyContract
  parent: #f
  revision: "architecture-content-causal-review"
  model-ids: '(rust.resources.backpressure-memory)
  slice-ids: '(rust.resources.backpressure-memory.integration)
  criteria: (list
             (.o
               identity: 'design-content-and-trace
               meaning: "Independently examine architecture, documents, decisions and their complete references against required obligations."
               duties: '(DE-O-ARCH DE-O-DOC DE-O-DEC DE-O-TRACE DE-O-REVIEW)
               inputs: '(architecture org decisions references)
               negative-controls: '(missing-content broken-reference history-as-current conflicting-decision)
               strength: 'authored-conditional)
             (.o
               identity: 'causal-change-and-authority
               meaning: "Reassess changed causal premises and preserve counterevidence, conflicts, vetoes and use restrictions through review and delivery."
               duties: '(DE-O-REVIEW)
               inputs: '(premises history roles authority recipient purpose)
               negative-controls: '(invalidated-premise unauthorized-role replay revoked-decision changed-use)
               strength: 'authored-conditional))
  required-products: '(D01 D02 D03 D04 D05 D06 D07 D08 D09 D10)
  required-roles: '(architecture-owner document-owner decision-owner independent-reviewer)
  conditions: (list
               (.o
                 identity: 'design-independent-check
                 inputs: '(architecture org decisions)
                 statement: "Declared presence and an inference view do not replace independent context and content verification.")
               (.o
                 identity: 'design-reassessment
                 inputs: '(premises history authority recipient purpose)
                 statement: "Premise invalidation, repair, exceptions, replacement, revocation and changed recipient use require explicit current decisions; research comparisons remain separate from correctness."))
  limitations: '("A selected policy defines duties; it is not a principal assignment, authorization, approval or delivery receipt."))

;; Each operation has an authored contract and complete required input classes.
;; Capturing those classes and their actual origins is a later operation boundary.
(.def ResourceMethod.
  operation: (error "Resource method requires an explicit operation")
  identity: (string->symbol (string-append "rust.resources." (symbol->string operation)))
  revision: "resource-method-observation"
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
  revision: "resource-method-observation"
  owner: 'rust-resources)
(.def (MethodObserverAsset @ ResourceMethodAsset.)
  identity: 'observer
  kind: 'scheme
  relative-path: "methods.ss")
(def RustMethodDefinitions
  (.o
    native: (.o (:: @ ResourceMethod.)
                operation: 'native
                model-ids: '(rust.resources.backpressure-memory)
                claims: (map (lambda (case-value) (car (.get case-value obligations))) integration-case-definitions)
                assets: (list
                         (.o (:: @ ResourceMethodAsset.)
                             identity: 'native-subject
                             kind: 'rust
                             relative-path: "native/src/main.rs")
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
                            kind: 'quint
                            relative-path: "../model.qnt")
                        MethodObserverAsset))
    lean: (.o (:: @ ResourceMethod.)
              operation: 'lean
              model-ids: '(concurrency.resource-control.backpressure-memory rust.resources.backpressure-memory)
              claims: '(BP-O03)
              assets: (list
                       (.o (:: @ ResourceMethodAsset.)
                           identity: 'budget-proof
                           kind: 'lean
                           relative-path: "../budget.lean")
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
