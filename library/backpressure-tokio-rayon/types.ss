;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Authored Tokio/Rayon model, correspondence and review contracts; no execution.
(import :clan/poo/object
  (only-in :clan/poo/mop map-object-values)
  (only-in :clan/poo/recursive-validation close-validation closed? closed-ref closed-names)
  (only-in :clan/poo/mop Type Type. Function define-type element? raise-type-error)
  (only-in :clan/poo/type String Symbol List Record Exactly)
  (only-in :clan/poo/object-contract ObjectContract. refine)
  (only-in :yuanxu/object-types/contracts YuanxuContract. yuanxu-predicate-type)
  (only-in :std/list/list duplicates)
  "../../types.ss"
  "../backpressure-memory/types.ss")
(export
  BackpressureScopeContract
  TokioRayonScopeContract
  TokioRayonConfigContract
  RustResourceModelContract
  RustModelShape
  BackpressureIntegrationContract
  BackpressureOwnershipCatalogContract
  BackpressureTraceMappingContract
  BackpressureReviewPolicyContract
  BackpressureDesignReviewPolicyContract
  resource-model-initializer
  resource-model-profile-supported?)
(def (unique? values) (null? (duplicates values)))
(def (slots? value names)
  (and (object? value) (andmap (cut .slot? value <>) names)))
;; Finite authored model coverage. Admission and execution use this one table;
;; neither capacity nor a Profile label can select an undeclared initializer.
(def ResourceModelInitializers
  (.o
    normal: '(((1 1) . "initResource") ((2 2) . "init") ((4 2) . "initC2"))
    early-release: '(((1 1) . "initResourceRunning") ((2 2) . "initRunning"))))
(def (resource-model-initializer value mode)
  (and
   (slots? value '(capacity queue))
   (symbol? mode)
   (.slot? ResourceModelInitializers mode)
   (let (selected
         (assoc (list (.get value capacity) (.get value queue)) (.ref ResourceModelInitializers mode)))
     (and selected (cdr selected)))))
(def (resource-model-profile-supported? value mode)
  (and (resource-model-initializer value mode) #t))
(def RustModelShape
  (.cc BackpressureModelShape 'responsibilities
       (.+
        (.get BackpressureModelShape responsibilities)
        (.o
          design: String
          trajectories: (List String)
          state-map: (List LibrarySymbolPair)))))
(def (complete-state-map? value inherited-model)
  (def mapping (.get value state-map))
  (def states (.get value lifecycle))
  (and
   (unique? states)
   (= (length mapping) (length states))
   (unique? (map car mapping))
   (andmap
    (lambda (row)
      (and (memq (car row) states) (memq (cadr row) (.get inherited-model lifecycle))))
    mapping)))
(def RustResourceModelContract
  (library-definition-contract
   'rust-resources/model
   'specialization
   'concurrency.resource-control.backpressure-memory
   BackpressureDeclarationContract
   (refine
    RustModelShape
    (lambda (value location)
      (def parent (.get value parent))
      (if (and
           (eq? (.get value identity) 'rust.resources.backpressure-memory)
           (backpressure-model? parent)
           (complete-state-map? value parent)
           (andmap (cut member <> (.get value rules)) (.get parent rules))
           (andmap (cut member <> (.get value dependencies)) (.get parent dependencies))
           (andmap (cut member <> (.get value factor-implications)) (.get parent factor-implications)))
          '()
          (list (.o kind: 'rust-resources/parent-or-obligation-loss path: location)))))))
;; Finite domain data. Execution/rendering interprets these definitions; it does
;; not own another case inventory, transition meaning or model extension.
(def TraceStage
  (yuanxu-predicate-type
   'backpressure/trace-stage
   (lambda (value) (and (memq value '(waiting queued running returned cleanup done)) #t))))
(def TraceEffectStage
  (yuanxu-predicate-type
   'backpressure/trace-effect-stage
   (lambda (value) (and (memq value '(unchanged waiting queued running returned cleanup done)) #t))))
(def ReservationEffect
  (yuanxu-predicate-type
   'backpressure/reservation-effect
   (lambda (value) (and (memq value '(keep reserve release)) #t))))
(def TraceCase
  (.cc ObjectContract. 'responsibilities
       (.o
         name: LibraryNonemptyString
         factor: Symbol
         obligations: LibrarySymbolTriple
         labels: (List String))))
(def TraceTransition
  (.cc ObjectContract. 'responsibilities
       (.o
         event: LibraryNonemptyString
         cases: (List String)
         from: (List TraceStage)
         to: TraceEffectStage
         reservation: ReservationEffect)))
(def QueuedDisposalDelta
  (refine
   (.cc ObjectContract. 'responsibilities
        (.o
          identity: Symbol
          from: Symbol
          to: Symbol
          subject: (yuanxu-predicate-type
                    'backpressure/job-zero
                    (lambda (value) (and (exact-integer? value) (= value 0))))
          frame: (List Symbol)))
   (lambda (value location)
     (if (and
          (not (eq? (.get value from) (.get value to)))
          (unique? (cons (.get value from) (cons (.get value to) (.get value frame)))))
         '()
         (list (.o kind: 'backpressure/delta-frame path: location))))))
(def DefinitionShape
  (.cc ObjectContract. 'responsibilities
       (.o
         identity: Symbol
         revision: LibraryNonemptyString
         owner: Symbol
         role: LibraryDefinitionRole
         family: Symbol
         declaration-contract: Type
         contract: Type
         parent: (yuanxu-predicate-type 'backpressure/definition-root not))))
(def OwnershipCatalogShape
  (.cc DefinitionShape 'responsibilities
       (.+
        (.get DefinitionShape responsibilities)
        (.o
          asset: LibraryAssetContract
          package: Symbol
          definition: Symbol
          attributes: (List Symbol)
          live-attribute: Symbol
          reservation-attribute: Symbol
          constraint: Symbol
          references: (List Symbol)))))
(def BackpressureOwnershipCatalogContract
  (library-definition-contract
   'backpressure/ownership-catalog
   'catalog
   'concurrency.resource-control.backpressure-memory
   BackpressureDeclarationContract
   (refine
    OwnershipCatalogShape
    (lambda (value location)
      (def asset-value (.get value asset))
      (def path (.get asset-value relative-path))
      (if (and
           (unique? (.get value attributes))
           (not (eq? (.get value live-attribute) (.get value reservation-attribute)))
           (memq (.get value live-attribute) (.get value attributes))
           (memq (.get value reservation-attribute) (.get value attributes))
           (eq? (.get asset-value kind) 'sysml)
           (eq? (.get asset-value owner) (.get value owner))
           (not (string-prefix? "/" path))
           (andmap
            (lambda (part) (and (not (string-empty? part)) (not (member part '("." "..")))))
            (string-split path #\/)))
          '()
          (list (.o kind: 'backpressure/catalog-binding path: location)))))))
(def TraceMappingShape
  (.cc DefinitionShape 'responsibilities
       (.+
        (.get DefinitionShape responsibilities)
        (.o
          catalog-id: Symbol
          cases: (List TraceCase)
          transitions: (List TraceTransition)
          initial: TraceStage
          final: TraceStage
          cut-labels: (List String)
          qnt-stages: (List Symbol)
          qnt-fields: (List Symbol)
          qnt-initializer: Symbol
          qnt-step: Symbol
          delta: QueuedDisposalDelta
          loss: LibraryNonemptyString))))
(def BackpressureTraceMappingContract
  (library-definition-contract
   'backpressure/trace-mapping
   'mapping
   'concurrency.resource-control.backpressure-memory
   BackpressureDeclarationContract
   (refine
    TraceMappingShape
    (lambda (value location)
      (def case-values (.get value cases))
      (def delta-value (.get value delta))
      (def fields (.get value qnt-fields))
      (if (and
           (pair? case-values)
           (unique? (map (cut .get <> name) case-values))
           (unique? (map (cut .get <> obligations) case-values))
           (unique? fields)
           (unique? (.get value qnt-stages))
           (equal?
            (list-sort (lambda (left right) (string<? (symbol->string left) (symbol->string right))) fields)
            (list-sort
             (lambda (left right) (string<? (symbol->string left) (symbol->string right)))
             (cons (.get delta-value from) (cons (.get delta-value to) (.get delta-value frame)))))
           (andmap (cut memq <> (.get value qnt-stages)) (list (.get delta-value from) (.get delta-value to)))
           (andmap
            (lambda (transition)
              (andmap
               (lambda (name) (member name (map (cut .get <> name) case-values)))
               (.get transition cases)))
            (.get value transitions)))
          '()
          (list (.o kind: 'backpressure/mapping-closure path: location)))))))
(def BackpressureIntegrationContract
  (library-definition-contract
   'rust-resources/integration
   'integration
   'concurrency.resource-control.backpressure-memory
   BackpressureDeclarationContract
   (refine
    (.cc RustModelShape 'responsibilities
         (.+
          (.get RustModelShape responsibilities)
          (.o
            case-links: (List LibrarySymbolTriple)
            mapping: (.get BackpressureTraceMappingContract value-contract)
            catalog: (.get BackpressureOwnershipCatalogContract value-contract))))
    (lambda (value location)
      (def parent (.get value parent))
      (if (and
           (eq? (.get value identity) 'rust.resources.backpressure-memory.integration)
           (element? (.get RustResourceModelContract value-contract) parent)
           (equal? (.get value lifecycle) (.get parent lifecycle))
           (equal? (.get value state-map) (.get parent state-map))
           (eq? (.get value mapping catalog-id) (.get value catalog identity))
           (equal? (.get value case-links) (map (cut .get <> obligations) (.get value mapping cases)))
           (andmap (cut member <> (.get value rules)) (.get parent rules))
           (andmap (cut member <> (.get value dependencies)) (.get parent dependencies))
           (andmap (cut member <> (.get value factor-implications)) (.get parent factor-implications)))
          '()
          (list
           (.o
             kind: 'rust-resources/integration-parent-or-obligation-loss
             path: location)))))))
;; Policy applicability is declaration data, separate from Aitia request domains.
(def PolicyCriterion
  (.cc ObjectContract. 'responsibilities
       (.o
         identity: Symbol
         meaning: LibraryNonemptyString
         duties: (List Symbol)
         inputs: (List Symbol)
         negative-controls: (List Symbol)
         strength: LibraryStrength)))
(def PolicyShape
  (.cc ObjectContract. 'responsibilities
       (.o
         identity: Symbol
         role: LibraryDefinitionRole
         family: Symbol
         declaration-contract: Type
         contract: Type
         parent: (yuanxu-predicate-type 'policy/root not)
         revision: LibraryNonemptyString
         model-ids: (List Symbol)
         slice-ids: (List Symbol)
         criteria: (List PolicyCriterion)
         required-products: (List Symbol)
         required-roles: (List Symbol)
         conditions: (List LibraryPremiseContract)
         limitations: (List String))))
(def (policy-shape identity-value products duties)
  (refine
   PolicyShape
   (lambda (value location)
     (def criteria (.get value criteria))
     (def actual-duties (apply append (map (cut .get <> duties) criteria)))
     (if (and
          (eq? (.get value identity) identity-value)
          (equal? (.get value model-ids) '(rust.resources.backpressure-memory))
          (equal? (.get value slice-ids) '(rust.resources.backpressure-memory.integration))
          (andmap (cut memq <> (.get value required-products)) products)
          (andmap (cut memq <> actual-duties) duties)
          (unique? (map (cut .get <> identity) criteria))
          (memq 'independent-reviewer (.get value required-roles)))
         '()
         (list
          (.o
            kind: 'rust-resources/policy-applicability-or-duty-loss
            path: location))))))
(def BackpressureReviewPolicyContract
  (library-definition-contract
   'rust-resources/coding-policy
   'policy
   'concurrency.resource-control.backpressure-memory
   BackpressureDeclarationContract
   (policy-shape
    'rust.resources.backpressure-memory.review-policy
    '(source-inventory method-results counterevidence)
    '(RL-M01 RL-M02 RL-M03 RL-M04 RL-M05 BP-O02 BP-O03))))
(def BackpressureDesignReviewPolicyContract
  (library-definition-contract
   'rust-resources/design-policy
   'policy
   'concurrency.resource-control.backpressure-memory
   BackpressureDeclarationContract
   (policy-shape
    'rust.resources.backpressure-memory.design-review-policy
    '(D01 D02 D03 D04 D05 D06 D07 D08 D09 D10)
    '(DE-O-ARCH DE-O-DOC DE-O-DEC DE-O-TRACE DE-O-REVIEW))))


;; Native Module admission for authored meaning; these functions execute no tools.
(def TokioRayonConfigShape
  (Record
    purpose: [(Exactly 'tokio-rayon-authored-model)]
    coding-policy: [(.get BackpressureReviewPolicyContract value-contract)]
    design-policy: [(.get BackpressureDesignReviewPolicyContract value-contract)]
    catalog: [(.get BackpressureOwnershipCatalogContract value-contract)]
    mapping: [(.get BackpressureTraceMappingContract value-contract)]
    cases: [(List TraceCase)]))
(def TokioRayonConfigContract
  (.cc YuanxuContract. 'identity 'tokio-rayon/config 'value-contract TokioRayonConfigShape))
(def TokioRayonParentModel
  (yuanxu-predicate-type
    'tokio-rayon/parent-model
    (lambda (value)
      (element? (.get RustResourceModelContract value-contract) value))))
(def TokioRayonScopeShape
  (Record
    config: [TokioRayonConfigShape]
    parent: [(.get BackpressureScopeContract value-contract)]
    contracts: [(Record
      config: [(Exactly TokioRayonConfigContract)]
      scope: [(yuanxu-predicate-type 'tokio-rayon/scope-contract
                (lambda (value) (eq? value TokioRayonScopeContract)))])]
    specialize: [(Function (list (.get RustResourceModelContract value-contract))
                    (list (List LibraryReferenceContract)))]
    integrate: [(Function (list (.get BackpressureIntegrationContract value-contract))
                   (list TokioRayonParentModel LibraryReferenceContract))]))
(defstruct model-normalization (graph) final: #t)
(def (closed-model-scope? value)
  (and
    (object? value)
    (.slot? value 'validation)
    (model-normalization? (.get value validation))
    (let (graph (model-normalization-graph (.get value validation)))
      (and
        (closed? graph)
        (equal? (closed-names graph) '(scope))
        (let* ((canonical (closed-ref graph 'scope))
               (names (.all-slots canonical)))
          (and
            (= (length (.all-slots value)) (1+ (length names)))
            (andmap (lambda (name) (eq? (.ref value name) (.ref canonical name))) names)))))))
(define-type
  (TokioRayonScopeType @ Type.)
  .element?:
  (lambda (value)
    (if (and (object? value) (.slot? value 'validation))
        (closed-model-scope? value)
        (element? TokioRayonScopeShape value)))
  .validate:
  (lambda (value)
    (if (and (object? value) (.slot? value 'validation))
        (begin
          (unless (closed-model-scope? value) (raise-type-error @ value))
          value)
        (let ()
          (unless (element? TokioRayonScopeShape value) (raise-type-error @ value))
          (def graph
            (close-validation
              (lambda (_reference) (list (list 'scope TokioRayonScopeShape value))) 1))
          ;; As with the existing Scenario owner, freeze admitted Record getters
          ;; before attaching proof metadata; later admission preserves identity.
          (.cc (map-object-values identity (closed-ref graph 'scope))
            'validation (make-model-normalization graph))))))
(def TokioRayonScopeContract
  (.cc YuanxuContract. 'identity 'tokio-rayon/scope 'value-contract TokioRayonScopeType))
