;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; -*- Gerbil -*-
(import
  :clan/poo/object
  (only-in :clan/poo/mop Type Type. Any Function define-type element? raise-type-error)
  (only-in :clan/poo/recursive-validation close-validation closed? closed-ref)
  (only-in
   :yuanxu/object-types/contracts
   YuanxuContract.
   yuanxu-predicate-contract
   yuanxu-predicate-type)
  (only-in :clan/poo/type String Symbol List Record)
  (only-in :std/list/list duplicates)
  (only-in :clan/poo/object-contract ObjectContract. refine)
  "../../types.ss"
  "../backpressure-tokio-rayon/types.ss"
  (only-in
   "../backpressure-memory/types.ss"
   BackpressureScopeContract
   BackpressureDeclarationContract
   BackpressureModelContract
   backpressure-model?))
(export
  ResourceMethodRequirements
  TokioRayonScopeContract
  ResourceMethodDefinitionContract
  ResourceMethodDefinitionsShape
  ResourceQuintSignature
  ResourceLeanSignature
  ResourceNativeSignature
  ResourceIntegrationSignature
  BackpressureTraceMappingContract
  BackpressureOwnershipCatalogContract
  RustResourcesConfigContract
  BackpressureReviewPolicyContract
  BackpressureDesignReviewPolicyContract
  RustResourceModelContract
  BackpressureIntegrationContract
  RustResourcesScopeContract
  ResourceProfileContract
  ResourceNativeProfileContract
  ResourceNativeContextContract
  resource-model-profile-supported?
  resource-model-initializer
  BackpressureScopeContract)
(def (unique? values) (null? (duplicates values)))
(def (slots? value names)
  (and (object? value) (andmap (cut .slot? value <>) names)))
(def (resource-profile? value)
  (and
   (slots?
    value
    '(identity
      capacity
      queue
      item
      fixed
      budget
      cache-bytes
      factors
      workload
      runtime
      inventory
      tokio-workers
      rayon-workers
      cpu-budget
      lock))
   (symbol? (.ref value 'identity))
   (andmap
    (lambda (key)
      (let (v (.ref value key))
        (and (integer? v) (exact? v) (> v 0))))
    '(capacity queue item budget tokio-workers rayon-workers cpu-budget))
   (andmap
    (lambda (key)
      (let (v (.ref value key))
        (and (integer? v) (exact? v) (>= v 0))))
    '(fixed cache-bytes))
   (resource-model-profile-supported? value 'normal)
   (list? (.ref value 'factors))
   (andmap symbol? (.ref value 'factors))
   (unique? (.ref value 'factors))
   (memq 'bounded-retention (.ref value 'factors))
   (andmap (lambda (key) (string? (.ref value key))) '(workload runtime inventory lock))))
(def (native-profile? value)
  (and
   (resource-profile? value)
   (equal? (.ref value 'runtime) "current-thread/rayon1/unwind")
   (equal? (.ref value 'inventory) "unique-owned-payload/permit")
   (equal? (.ref value 'lock) "captured-by-native-method")
   (equal?
    (.ref value 'workload)
    (string-append "controlled-six-case-suite/" (number->string (.ref value 'item))))
   (andmap
    (cut memq <> (.ref value 'factors))
    '(bounded-retention
      tokio
      rayon
      normal-handoff
      admission-cancellation
      abandoned-result
      caller-abort
      cleanup-full
      caller-owned-permit))
   (andmap
    (lambda (key) (= (.ref value key) 1))
    '(capacity queue tokio-workers rayon-workers cpu-budget))
   (= (.ref value 'cache-bytes) 0)
   (<= (.ref value 'item) 4096)))
(def (entry? value)
  (and
   (object? value)
   (.slot? value 'contract)
   (cond
    ((eq? (.get value contract) RustResourceModelContract)
     ((.ref (.get RustResourceModelContract value-contract) '.element?) value))
    ((eq? (.get value contract) BackpressureIntegrationContract)
     ((.ref (.get BackpressureIntegrationContract value-contract) '.element?) value))
    (else #f))))
(def (native-context? value)
  (and
   (slots? value '(root entry profile crate cargo rustc mode usage snapshot scopes))
   (entry? (.ref value 'entry))
   (native-profile? (.ref value 'profile))
   (resource-model-profile-supported? (.ref value 'profile) (.ref value 'mode))
   (andmap
    (lambda (key) (let (v (.ref value key)) (and (string? v) (> (string-length v) 0))))
    '(root crate cargo rustc snapshot))
   (symbol? (.ref value 'usage))
   (list? (.ref value 'scopes))
   (andmap
    (lambda (r)
      (and
       (list? r)
       (= (length r) 3)
       (eq? (car r) (.ref value 'usage))
       (symbol? (cadr r))
       (string? (caddr r))
       (> (string-length (caddr r)) 0)))
    (.ref value 'scopes))
   (= (length (.ref value 'scopes)) 7)
   (unique? (map cadr (.ref value 'scopes)))
   (andmap
    (cut member <> (map cadr (.ref value 'scopes)))
    '(model arithmetic cache source runtime workload inventory))))
(def PositiveCount
  (yuanxu-predicate-type
   'rust-resources/positive-count
   (lambda (value) (and (exact-integer? value) (> value 0)))))
(def NonnegativeCount
  (yuanxu-predicate-type
   'rust-resources/nonnegative-count
   (lambda (value) (and (exact-integer? value) (>= value 0)))))
(def ResourceProfileShape
  (.cc ObjectContract. 'responsibilities
       (.o
         identity: Symbol
         capacity: PositiveCount
         queue: PositiveCount
         item: PositiveCount
         fixed: NonnegativeCount
         budget: PositiveCount
         cache-bytes: NonnegativeCount
         tokio-workers: PositiveCount
         rayon-workers: PositiveCount
         cpu-budget: PositiveCount
         factors: (List Symbol)
         workload: LibraryNonemptyString
         runtime: LibraryNonemptyString
         inventory: LibraryNonemptyString
         lock: LibraryNonemptyString)))
(def (bounded-profile-shape predicate-value)
  (refine
   ResourceProfileShape
   (lambda (value location)
     (if (predicate-value value)
         '()
         (list (.o kind: 'rust-resources/unsupported-profile path: location))))))
(def ResourceProfileContract
  (.cc YuanxuContract. 'identity 'rust-resources/profile
       'value-contract (bounded-profile-shape resource-profile?)))
(def ResourceNativeProfileContract
  (.cc YuanxuContract. 'identity 'rust-resources/native-profile
       'value-contract (bounded-profile-shape native-profile?)))
(def ResourceNativeContextContract
  (.cc YuanxuContract. 'identity 'rust-resources/native-context
       'value-contract
       (refine
        (.cc ObjectContract. 'responsibilities
             (.o
               root: LibraryNonemptyString
               entry: (yuanxu-predicate-type 'rust-resources/expected-model entry?)
               profile: (.get ResourceNativeProfileContract value-contract)
               crate: LibraryNonemptyString
               cargo: LibraryNonemptyString
               rustc: LibraryNonemptyString
               mode: (yuanxu-predicate-type
                      'rust-resources/model-mode
                      (lambda (value) (and (memq value '(normal early-release)) #t)))
               usage: Symbol
               snapshot: LibraryNonemptyString
               scopes: (List LibraryScopeBinding)))
        (lambda (value location)
          (if (native-context? value)
              '()
              (list (.o kind: 'rust-resources/context-selection-mismatch path: location)))))))
(def method-keys
  '(native-oracle
    native
    native-scopes
    native-context
    context-current!
    integration-scopes
    integration
    scopes
    quint
    lean
    register
    record
    id
    reference
    claim
    current!
    file-digest
    value-digest
    write-json))
(def (same-type identity-value expected)
  (yuanxu-predicate-type identity-value (lambda (value) (eq? value expected))))
(def RustResourcesConfigShape
  (.cc ObjectContract. 'responsibilities
       (.o
         purpose: (same-type 'rust-resources/config-purpose 'rust-resource-method-driver)
         coding-policy: (.get BackpressureReviewPolicyContract value-contract)
         design-policy: (.get BackpressureDesignReviewPolicyContract value-contract))))
(def RustResourcesConfigContract
  (.cc YuanxuContract. 'identity 'rust-resources/config 'value-contract RustResourcesConfigShape))
(def PolicySelectionShape
  (.cc ObjectContract. 'responsibilities
       (.o
         coding: (.get BackpressureReviewPolicyContract value-contract)
         design: (.get BackpressureDesignReviewPolicyContract value-contract))))
;; Function owns arity, optional arguments and checked call boundaries. Any
;; result here is structural only; methods.ss alone recognizes issued results.
(def ResourceQuintSignature
  (Function
   (list Any)
   (list
    LibraryNonemptyString
    (.get ResourceProfileContract value-contract)
    LibraryNonemptyString
    LibraryNonemptyString)
   optional:
   (list
    (yuanxu-predicate-type
     'rust-resources/quint-mode
     (lambda (v) (and (memq v '(normal early-release)) #t))))))
(def ResourceLeanSignature
  (Function
   (list Any)
   (list
    LibraryNonemptyString
    (.get ResourceProfileContract value-contract)
    LibraryNonemptyString
    LibraryNonemptyString)))
(def ResourceNativeSignature
  (Function
   (list (List Any))
   (list
    LibraryNonemptyString
    LibraryNonemptyString
    LibraryNonemptyString
    LibraryNonemptyString
    (yuanxu-predicate-type
     'rust-resources/payload-bytes
     (lambda (v) (and (exact-integer? v) (> v 0) (<= v 4096))))
    LibraryNonemptyString)))
(def ResourceIntegrationSignature
  (Function
   (list (List Any))
   (list
    (.get ResourceNativeContextContract value-contract)
    (List Any)
    LibraryNonemptyString
    LibraryNonemptyString
    LibraryNonemptyString)))
;; Published expectations are independent of submitted method definitions.
;; One finite operation axis; these are data requirements, not Provider dispatch.
(def ResourceMethodRequirements
  (.o
    native: (.o
              signature: ResourceNativeSignature
              kind: 'implementation-execution
              strength: 'execution
              modes: '(normal)
              inputs: '(source
                        runtime
                        workload
                        inventory
                        profile
                        cargo-lock
                        compiler
                        configuration
                        registry-inputs
                        executable
                        interpretation-source
                        compiled-origins))
    quint: (.o
             signature: ResourceQuintSignature
             kind: 'model-verification
             strength: 'finite-model
             modes: '(normal early-release)
             inputs: '(model profile tool tool-dependencies runtime interpretation-source compiled-origins))
    lean: (.o
            signature: ResourceLeanSignature
            kind: 'theorem-check
            strength: 'arithmetic
            modes: '(normal)
            inputs: '(arithmetic profile tool tool-dependencies runtime interpretation-source compiled-origins))
    integration: (.o
                   signature: ResourceIntegrationSignature
                   kind: 'model-projection
                   strength: 'correspondence
                   modes: '(normal)
                   inputs: '(source
                             runtime
                             workload
                             inventory
                             model
                             native-results
                             mapping
                             catalog
                             reference-closure
                             tools
                             tool-dependencies
                             interpretation-source
                             compiled-origins))))
(def ResourceMethodDefinitionContract
  (library-definition-contract
   'rust-resources/method
   'method
   'concurrency.resource-control.backpressure-memory
   BackpressureDeclarationContract
   (refine
    LibraryMethodShape
    (lambda (v location)
      (def operation-key (.get v operation))
      (def expected
        (and
         (.slot? ResourceMethodRequirements operation-key)
         (.ref ResourceMethodRequirements operation-key)))
      (if (and
           expected
           (eq? (.get v signature) (.get expected signature))
           (eq? (.get v kind) (.get expected kind))
           (eq? (.get v strength) (.get expected strength))
           (equal? (.get v modes) (.get expected modes))
           (eq? (.get v provider) 'rust-resources)
           (eq? (.get v result-owner) 'rust-resources)
           (pair? (.get v model-ids))
           (pair? (.get v claims))
           (pair? (.get v modes))
           (pair? (.get v input-demands))
           (unique? (.get v input-demands))
           (unique? (.get v model-ids))
           (unique? (.get v policy-ids))
           (unique? (.get v claims))
           (andmap (cut memq <> (.get v input-demands)) (.get expected inputs))
           (pair? (.get v assets))
           (memq 'interpretation-source (.get v input-demands))
           (memq 'compiled-origins (.get v input-demands)))
          '()
          (list (.o kind: 'rust-resources/method-binding-demand path: location)))))))
(def ResourceMethodDefinitionsShape
  (.cc ObjectContract. 'responsibilities
       (.o
         native: (.get ResourceMethodDefinitionContract value-contract)
         quint: (.get ResourceMethodDefinitionContract value-contract)
         lean: (.get ResourceMethodDefinitionContract value-contract)
         integration: (.get ResourceMethodDefinitionContract value-contract))))

;; The public Module supplies declarations and specialization, not a tool Runtime.
(define-type RustMethodScopeType
  (.cc
    (Record config: [(.get RustResourcesConfigContract value-contract)]
            contracts: [Object]
            definitions: [ResourceMethodDefinitionsShape]
            parent: [Object]
            model-library: [Object]
            policies: [PolicySelectionShape]
            entry: [(.get RustResourceModelContract value-contract)]
            integration-entry: [(.get BackpressureIntegrationContract value-contract)]
            profile-contract: [Type]
            native-profile-contract: [Type])
    'identity 'rust-resources/declaration-scope))
(def RustResourcesScopeContract
  (.cc YuanxuContract. 'identity 'rust-resources/scope
       'value-contract RustMethodScopeType))
