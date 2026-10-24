;;; -*- Gerbil -*-
(import :clan/poo/object "types.ss"
        (only-in "../abstract/types.ss" BackpressureDeclarationContract))
(export RustMethodDefinitions specialize-backpressure make-backpressure-integration
        BackpressureCodingPolicy BackpressureDesignPolicy)
(def (specialize-backpressure BackpressureModel)
 (.+ BackpressureModel (.o
  identity: 'rust.resources.backpressure-memory
  revision: "backpressure/v3"
  role: 'specialization contract: RustResourceModelContract
  parent: BackpressureModel
  design: "10.17"
  trajectories: '("10.10" "10.11" "10.15")
  lifecycle: '(waiting queued cpu-running result-pending cleanup released)
  state-map: '((waiting waiting) (queued queued) (cpu-running active)
               (result-pending returned) (cleanup cleanup) (released released))
  rules: (append (.ref BackpressureModel 'rules)
    '(
      (bounded-retention BP-O04 review)
      (bounded-retention BP-O07 native)
      (tokio TR-O01 native)
      (rayon TR-O02 review)
      (async-cpu-handoff TR-O03 quint)
      (cache CA-O01 native)
      (retry BP-O05 quint)
      (normal-handoff RL-M01 native)
      (admission-cancellation RL-M02 native)
      (abandoned-result RL-M03 native)
      (caller-abort RL-M04 native)
      (cleanup-full RL-M05 native)
      (caller-owned-permit RL-M06 native)))
  dependencies: (append (.ref BackpressureModel 'dependencies)
    '(
      (BP-O04 model)
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
      (BP-O05 runtime)
      (RL-M01 source)
      (RL-M01 runtime)
      (RL-M01 workload)
      (RL-M01 inventory)
      (RL-M02 source)
      (RL-M02 runtime)
      (RL-M02 workload)
      (RL-M02 inventory)
      (RL-M03 source)
      (RL-M03 runtime)
      (RL-M03 workload)
      (RL-M03 inventory)
      (RL-M04 source)
      (RL-M04 runtime)
      (RL-M04 workload)
      (RL-M04 inventory)
      (RL-M05 source)
      (RL-M05 runtime)
      (RL-M05 workload)
      (RL-M05 inventory)
      (RL-M06 source)
      (RL-M06 runtime)
      (RL-M06 workload)
      (RL-M06 inventory)))
  method-refs: (map (lambda (key) (method-ref (.ref RustMethodDefinitions key))) '(native quint lean))
  qualification: 'authored-specialization)))

;; One authored inventory and one typed transition/delta meaning.
(def (trace-case case-name factor-value labels-value)
 (let (name-value case-name)
  (.o name: name-value factor: factor-value labels: labels-value
      obligations: (map (lambda (prefix) (string->symbol (string-append prefix name-value))) '("RL-" "SI-" "TM-")))))
(def common-labels '("payload-created" "payload-dropped" "held" "final"))
(def worker-labels '("cpu-started" "started" "cpu-released" "cpu-finished"))
(def integration-case-definitions
 (map (lambda (row)
  (trace-case (car row) (cadr row)
   (append common-labels (if (equal? (car row) "M02") '() worker-labels) (caddr row))))
  '(("M01" normal-handoff ("returned"))
    ("M02" admission-cancellation ("waiter-pending" "waiter-cancelled"))
    ("M03" abandoned-result ("receiver-dropped" "delivery-failed-retained"))
    ("M04" caller-abort ("caller-waiting" "caller-cancelled" "delivery-failed-retained"))
    ("M05" cleanup-full ("cleanup-full-retained"))
    ("M06" caller-owned-permit ("caller-waiting" "caller-cancelled" "delivery-failed-retained")))))
(def integration-cases (map (cut .get <> name) integration-case-definitions))
(def integration-factors (map (cut .get <> factor) integration-case-definitions))
(def integration-native-keys '(source runtime workload inventory))
(def (transition event-value selected-cases before-stages after-stage reserve-effect)
 (.o event: event-value cases: selected-cases from: before-stages to: after-stage reservation: reserve-effect))
(.def OwnershipCatalog
 identity: 'backpressure.ownership-catalog revision: "observed-ownership-constraint"
 owner: 'rust-resources role: 'catalog family: 'concurrency.resource-control.backpressure-memory
 declaration-contract: BackpressureDeclarationContract contract: BackpressureOwnershipCatalogContract parent: #f
 asset: (.o identity: 'ownership-notation revision: "observed-ownership-constraint" owner: 'rust-resources
            kind: 'sysml relative-path: "ownership.sysml")
 package: 'BackpressureOwnership definition: 'Ownership attributes: '(live reserved)
 live-attribute: 'live reservation-attribute: 'reserved
 constraint: 'retainedRequiresReservation references: '(ScalarValues))
(.def TraceMapping
 identity: 'backpressure.observed-cuts revision: "single-job-observed-cuts/v1"
 owner: 'rust-resources role: 'mapping family: 'concurrency.resource-control.backpressure-memory
 declaration-contract: BackpressureDeclarationContract contract: BackpressureTraceMappingContract parent: #f
 catalog-id: (.get OwnershipCatalog identity) cases: integration-case-definitions
 initial: 'waiting final: 'done cut-labels: '("started" "held" "returned" "final")
 qnt-stages: '(queued running returned cleanup done)
 qnt-fields: '(limit queueLimit admitted queued running returned cleanup done)
 qnt-initializer: 'initResource qnt-step: 'step
 delta: (.o identity: 'cancelQueued from: 'queued to: 'cleanup subject: 0
             frame: '(limit queueLimit admitted running returned done))
 transitions: (list
  (transition "payload-created" '() '(waiting) 'queued 'reserve)
  (transition "cpu-started" '() '(queued) 'running 'keep)
  (transition "delivery-failed-retained" '() '(running) 'cleanup 'keep)
  (transition "cleanup-full-retained" '() '(running) 'cleanup 'keep)
  (transition "returned" '() '(running) 'returned 'keep)
  (transition "payload-dropped" '("M02") '(queued) 'cleanup 'keep)
  (transition "caller-cancelled" '("M06") '() 'unchanged 'release)
  (transition "final" '() '(cleanup returned) 'done 'release))
 loss: "Observed single-job cuts; queued cancellation extends the base model; not complete Rust refinement")
(def (make-backpressure-integration parent-model)
  (.+ parent-model (.o
    role: 'integration contract: BackpressureIntegrationContract
      method-refs: (append (.get parent-model method-refs) (list (method-ref (.get RustMethodDefinitions integration)))) parent: parent-model
    identity: 'rust.resources.backpressure-memory.integration
    revision: "backpressure-integration/v1"
    mapping: TraceMapping catalog: OwnershipCatalog
    case-links: (map (cut .get <> obligations) integration-case-definitions)
    rules: (append (.ref parent-model 'rules)
      (apply append (map (lambda (name factor)
        (list (list factor (string->symbol (string-append "SI-" name)) 'sysml)
              (list factor (string->symbol (string-append "TM-" name)) 'correspondence))) integration-cases integration-factors)))
    dependencies: (append (.ref parent-model 'dependencies)
      (apply append (map (lambda (name)
        (append (map (lambda (key) (list (string->symbol (string-append "SI-" name)) key))
                     (append integration-native-keys '(correspondence sysml-tool)))
                (map (lambda (key) (list (string->symbol (string-append "TM-" name)) key))
                     (append integration-native-keys '(correspondence quint-tool))))) integration-cases))))))

;; Two independent authored policies. Neither appoints principals or grants use.
(.def BackpressureCodingPolicy
 identity: 'rust.resources.backpressure-memory.review-policy
 role: 'policy family: 'concurrency.resource-control.backpressure-memory
 declaration-contract: BackpressureDeclarationContract contract: BackpressureReviewPolicyContract
 parent: #f revision: "controlled-ownership-coding-review"
 model-ids: '(rust.resources.backpressure-memory)
 slice-ids: '(rust.resources.backpressure-memory.integration)
 criteria: (list
  (.o identity: 'worker-owned-lifecycle meaning: "Review the five worker-owned permit paths under the selected controlled execution profile."
      duties: '(RL-M01 RL-M02 RL-M03 RL-M04 RL-M05) inputs: '(source runtime workload inventory)
      negative-controls: '(caller-owned-permit unbound-tool changed-input) strength: 'execution)
  (.o identity: 'bounded-formal-correspondence meaning: "Keep finite-model, arithmetic and observed-cut correspondence conclusions distinct."
      duties: '(BP-O02 BP-O03) inputs: '(model arithmetic correspondence)
      negative-controls: '(early-release unsupported-delta missing-cut) strength: 'authored-conditional))
 required-products: '(source-inventory method-results counterevidence)
 required-roles: '(implementation-owner independent-reviewer)
 conditions: (list
  (.o identity: 'coding-applicability inputs: '(source workload)
      statement: "The policy applies to the declared controlled worker-owned mechanism and preserves the caller-owned counterexample as investigation evidence.")
  (.o identity: 'coding-currentness inputs: '(source runtime inventory)
      statement: "Missing, conflicting, stale or weaker evidence remains visible; matching labels and historical successes cannot satisfy current duties."))
 limitations: '("Controlled suite qualification is not a production throughput claim or institutional classification."))
(.def BackpressureDesignPolicy
 identity: 'rust.resources.backpressure-memory.design-review-policy
 role: 'policy family: 'concurrency.resource-control.backpressure-memory
 declaration-contract: BackpressureDeclarationContract contract: BackpressureDesignReviewPolicyContract
 parent: #f revision: "architecture-content-causal-review"
 model-ids: '(rust.resources.backpressure-memory)
 slice-ids: '(rust.resources.backpressure-memory.integration)
 criteria: (list
  (.o identity: 'design-content-and-trace meaning: "Independently examine architecture, documents, decisions and their complete references against required obligations."
      duties: '(DE-O-ARCH DE-O-DOC DE-O-DEC DE-O-TRACE DE-O-REVIEW)
      inputs: '(architecture org decisions references)
      negative-controls: '(missing-content broken-reference history-as-current conflicting-decision)
      strength: 'authored-conditional)
  (.o identity: 'causal-change-and-authority meaning: "Reassess changed causal premises and preserve counterevidence, conflicts, vetoes and use restrictions through review and delivery."
      duties: '(DE-O-REVIEW) inputs: '(premises history roles authority recipient purpose)
      negative-controls: '(invalidated-premise unauthorized-role replay revoked-decision changed-use)
      strength: 'authored-conditional))
 required-products: '(D01 D02 D03 D04 D05 D06 D07 D08 D09 D10)
 required-roles: '(architecture-owner document-owner decision-owner independent-reviewer)
 conditions: (list
  (.o identity: 'design-independent-check inputs: '(architecture org decisions)
      statement: "Declared presence and an inference view do not replace independent context and content verification.")
  (.o identity: 'design-reassessment inputs: '(premises history authority recipient purpose)
      statement: "Premise invalidation, repair, exceptions, replacement, revocation and changed recipient use require explicit current decisions; research comparisons remain separate from correctness."))
 limitations: '("A selected policy defines duties; it is not a principal assignment, authorization, approval or delivery receipt."))

;; Each operation has an authored contract and complete required input classes.
;; Capturing those classes and their actual origins is a later operation boundary.
(def (method-definition selected-operation selected-kind selected-strength selected-signature selected-models selected-claims selected-inputs selected-assets)
 (.o identity: (string->symbol (string-append "rust.resources." (symbol->string selected-operation)))
     revision: "resource-method-observation" owner: 'rust-resources role: 'method
     family: 'concurrency.resource-control.backpressure-memory
     declaration-contract: BackpressureDeclarationContract contract: ResourceMethodDefinitionContract
     kind: selected-kind strength: selected-strength signature: selected-signature
     provider: 'rust-resources operation: selected-operation result-owner: 'rust-resources
     model-ids: selected-models
     policy-ids: '(rust.resources.backpressure-memory.review-policy rust.resources.backpressure-memory.design-review-policy)
     claims: selected-claims modes: (if (eq? selected-operation 'quint) '(normal early-release) '(normal))
     result-kinds: '(observation counterevidence) input-demands: selected-inputs assets: selected-assets
     premises: (list (.o identity: 'complete-method-basis inputs: selected-inputs
       statement: "Execution must bind every declared input class, its actual source, tool/runtime dependencies and applicability."))
     limits: (list (.o identity: 'method-strength inputs: selected-inputs
       statement: "A completed command or local result is not C, authorization, universal refinement or an accepted current-use view."))
     program-ref: #f catalog-ref: (if (eq? selected-operation 'integration) (method-ref OwnershipCatalog) #f)
     mapping-ref: (if (eq? selected-operation 'integration) (method-ref TraceMapping) #f)))
(def (method-asset selected-name selected-kind selected-path)
 (.o identity: selected-name revision: "resource-method-observation" owner: 'rust-resources
     kind: selected-kind relative-path: selected-path))
(def RustMethodDefinitions
 (.o native: (method-definition 'native 'implementation-execution 'execution ResourceNativeSignature
       '(rust.resources.backpressure-memory) (map (lambda (c) (car (.get c obligations))) integration-case-definitions)
       '(source runtime workload inventory profile cargo-lock compiler configuration registry-inputs executable interpretation-source compiled-origins)
       (list (method-asset 'native-subject 'rust "native/src/main.rs") (method-asset 'observer 'scheme "methods.ss") (method-asset 'oracle 'scheme "oracle.ss")))
     quint: (method-definition 'quint 'model-verification 'finite-model ResourceQuintSignature
       '(concurrency.resource-control.backpressure-memory rust.resources.backpressure-memory) '(BP-O02)
       '(model profile tool tool-dependencies runtime interpretation-source compiled-origins)
       (list (method-asset 'ownership-model 'quint "../model.qnt") (method-asset 'observer 'scheme "methods.ss")))
     lean: (method-definition 'lean 'theorem-check 'arithmetic ResourceLeanSignature
       '(concurrency.resource-control.backpressure-memory rust.resources.backpressure-memory) '(BP-O03)
       '(arithmetic profile tool tool-dependencies runtime interpretation-source compiled-origins)
       (list (method-asset 'budget-proof 'lean "../budget.lean") (method-asset 'observer 'scheme "methods.ss")))
     integration: (method-definition 'integration 'model-projection 'correspondence ResourceIntegrationSignature
       '(rust.resources.backpressure-memory.integration) (apply append (map (lambda (c) (cdr (.get c obligations))) integration-case-definitions))
       '(source runtime workload inventory model native-results mapping catalog reference-closure tools tool-dependencies interpretation-source compiled-origins)
       (list (method-asset 'correspondence 'scheme "correspondence.ss") (.get OwnershipCatalog asset)))))

(def (method-ref definition-value)
 (.o identity: (.get definition-value identity) revision: (.get definition-value revision)
     owner: (.get definition-value owner)))
