;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-only

;;; -*- Gerbil -*-
;;; Native method admission preserves the selected owners and captured handles.
(import
  (only-in :clan/poo/object .get .ref .cc .all-slots object? .slot?)
  (only-in
   :clan/poo/mop
   Type.
   Object
   Function
   define-type
   element?
   raise-type-error
   map-object-values)
  (only-in :clan/poo/type Record Symbol Enum)
  (only-in :clan/poo/recursive-validation close-validation closed? closed-ref closed-names)
  (only-in :yuanxu/object-types/contracts YuanxuContract. yuanxu-predicate-type)
  (only-in :gerbil-ascent/program/types GerbilAscentSessionContract)
  (only-in "../../types.ss" LibraryNonemptyString)
  (only-in
   "../../library/drivers/rust-resources/types.ss"
   RustResourcesScopeContract)
  (only-in "../../library/drivers/evidence/types.ss" ResourceEvidenceScopeContract))

(export
  RustResourcesScopeContract
  ResourceEvidenceScopeContract
  ResourceLifecycleScopeContract)

;; The header admits only owner objects. The dependent Record checks all fields.
(define-type
  LifecycleScopeHeader
  (Record
    domain: [Object]
    evidence: [Object]
    contracts: [Object]
    entry: [Object]
    integration-entry: [Object]
    methods: [Object]))

;; A generic closed graph proves its own descriptor, not this Scenario's signature.
;; Keep its issuer ownership opaque; the native graph still owns all validation.
(defstruct lifecycle-normalization (graph) final: #t)
(define-type (LifecycleValidationProof @ Type.) .element?: lifecycle-normalization?)

(def (same-owner identity-value expected)
  (yuanxu-predicate-type identity-value (lambda (value) (eq? value expected))))

(def (lifecycle-scope-shape value)
  (and
   (element? LifecycleScopeHeader value)
   (element? RustResourcesScopeContract (.get value domain))
   (element? ResourceEvidenceScopeContract (.get value evidence))
   (let* ((selected-domain (.get value domain))
          (selected-evidence (.get value evidence))
          ;; Recognition keeps the existing owner's handles. It is not a cast:
          ;; full membership is checked, and current! remains at actual use.
          (context
           (yuanxu-predicate-type
            'resource-lifecycle/owned-context
            (cut element? (.get selected-domain context-contract) <>)))
          (profile
           (yuanxu-predicate-type
            'resource-lifecycle/owned-profile
            (cut element? (.get selected-domain native-profile-contract) <>)))
          (capture-signature
           (Function
            (list context)
            (list
             LibraryNonemptyString
             profile
             LibraryNonemptyString
             LibraryNonemptyString
             LibraryNonemptyString
             Symbol)
            optional:
            (list (Enum normal early-release))))
          (review-signature (Function (list GerbilAscentSessionContract) (list context))))
     (.cc
         (Record
           domain: [(same-owner 'resource-lifecycle/domain selected-domain)]
           evidence: [(same-owner 'resource-lifecycle/evidence selected-evidence)]
           contracts:
           [(.cc
                (Record
                  scope: [(same-owner 'resource-lifecycle/contract ResourceLifecycleScopeContract)])
              'sealed #t)]
           entry: [(same-owner 'resource-lifecycle/entry (.get selected-domain entry))]
           integration-entry:
           [(same-owner 'resource-lifecycle/integration (.get selected-domain integration-entry))]
           methods: [(same-owner 'resource-lifecycle/methods (.get selected-domain methods))]
           capture: [capture-signature]
           open-review: [review-signature])
       'sealed #t))))

(def (closed-lifecycle-scope? value)
  (and
   (object? value)
   (.slot? value 'validation)
   (lifecycle-normalization? (.get value validation))
   (closed? (lifecycle-normalization-graph (.get value validation)))
   (equal? (closed-names (lifecycle-normalization-graph (.get value validation))) '(scope))
   (let* ((canonical (closed-ref (lifecycle-normalization-graph (.get value validation)) 'scope))
          (shape (lifecycle-scope-shape canonical)))
     (and
      shape
      ;; The declared closed shape permits one additional owner-issued handle.
      (element?
       (.cc (Record (list shape) validation: (list LifecycleValidationProof)) 'sealed #t)
       value)
      ;; Membership of Function is callable recognition. The graph additionally
      ;; binds the exact wrappers installed by the original normalization.
      (andmap
       (lambda (name) (eq? (.ref value name) (.ref canonical name)))
       (.all-slots canonical))))))

(define-type
  (ResourceLifecycleScopeType @ Type.)
  .element?:
  (lambda (value)
    (if (and (object? value) (.slot? value 'validation))
        (closed-lifecycle-scope? value)
        (let (shape (lifecycle-scope-shape value))
          (and shape (element? shape value)))))
  .validate:
  (lambda (value)
    (if (and (object? value) (.slot? value 'validation))
        (begin
          (unless (closed-lifecycle-scope? value) (raise-type-error @ value))
          value)
        (let (shape (lifecycle-scope-shape value))
          (unless (and shape (element? shape value)) (raise-type-error @ value))
          (def graph
            (close-validation
             (lambda (_reference) (list (list 'scope shape value)))
             1))
          ;; A Record's inherited getters normalize for each receiver. Materialize
          ;; their admitted values before adding metadata, so functions are not
          ;; wrapped again merely because the public receiver acquired a graph.
          (.cc (map-object-values identity (closed-ref graph 'scope))
            'validation (make-lifecycle-normalization graph))))))

(define-type
  (ResourceLifecycleScopeContract @ YuanxuContract.)
  identity:
  'resource-lifecycle/scope
  value-contract:
  ResourceLifecycleScopeType)
