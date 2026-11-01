;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Shared Library declaration vocabulary. Types only: no objects, IO or Engine.
(import
  :clan/poo/object
  (only-in :clan/poo/mop Type Type. define-type element? raise-type-error)
  (only-in :clan/poo/type Symbol String List Record Pair Exactly)
  (only-in :clan/poo/recursive-validation close-validation closed? closed-ref)
  (only-in :clan/poo/object-contract ObjectContract. refine)
  (only-in :yuanxu/object-types/contracts YuanxuContract. yuanxu-predicate-type))
(export
  LibraryDeclarationContract
  LibraryDeclarationShape
  LibraryReferenceContract
  LibraryAssetContract
  LibraryPremiseContract
  LibraryClaimContract
  LibraryMethodShape
  LibraryMethodBindingShape
  LibraryModelShape
  LibraryMethodKind
  LibraryDefinitionRole
  LibraryStrength
  LibraryNonemptyString
  LibrarySymbolPair
  LibrarySymbolTriple
  LibraryScopeBinding
  library-definition-contract
  LibraryScopeType.)
(define-type
  (LibraryNonemptyString @ Type.)
  .element?:
  (lambda (value) (and (string? value) (> (string-length value) 0))))
(define-type LibrarySymbolPair
  (Pair Symbol (Pair Symbol (Exactly '()))))

(define-type LibrarySymbolTriple
  (Pair Symbol LibrarySymbolPair))

;; Shared wire binding: selected usage, scope kind and nonempty basis reference.
;; This shape does not establish digest validity, currentness or authority.
(define-type LibraryScopeBinding
  (Pair Symbol (Pair Symbol (Pair LibraryNonemptyString (Exactly '())))))

(def (finite-type identity-values choices)
  (yuanxu-predicate-type identity-values (lambda (value) (and (memq value choices) #t))))
(def LibraryDefinitionRole
  (finite-type
   'library/definition-role
   '(generic-model specialization integration organization policy method catalog mapping)))
(def LibraryMethodKind
  (finite-type
   'library/method-kind
   '(application-reasoning
     model-projection
     content-observation
     implementation-execution
     model-verification
     theorem-check)))
(def LibraryStrength
  (finite-type
   'library/strength
   '(authored-conditional
     finite-model
     arithmetic
     execution
     language-validation
     correspondence
     research-hypothesis)))
(define-type
  (LibraryReferenceContract
   @
   (Record
     identity: [Symbol]
     revision: [LibraryNonemptyString]
     owner: [Symbol]))
  sealed:
  #t)
(define-type
  (LibraryAssetContract
   @
   (Record [LibraryReferenceContract]
           kind: [(finite-type 'library/asset-kind '(scheme quint lean rust sysml org mapping))]
           relative-path: [LibraryNonemptyString]))
  sealed:
  #t)
(define-type
  (LibraryPremiseContract
   @
   (Record
     identity: [Symbol]
     statement: [LibraryNonemptyString]
     inputs: [(List Symbol)]))
  sealed:
  #t)
(define-type
  (LibraryClaimContract
   @
   (Record
     identity: [Symbol]
     meaning: [LibraryNonemptyString]
     premises: [(List Symbol)]
     duties: [(List Symbol)]
     strength: [LibraryStrength]))
  sealed:
  #t)
(def LibraryDeclarationShape
  (.cc ObjectContract. 'identity 'library/declaration
       'responsibilities (.o
                           identity: Symbol
                           family: Symbol
                           source-owner: Symbol
                           applicability: (List Symbol)
                           role-contracts: (List Type)
                           extension-expectations: (List Symbol))))
;; The sole authored Library contract generation. Family declarations inherit it;
;; definitions, Scope values, Profiles, Scenarios and views carry references.
(def LibraryDeclarationContract
  (.cc YuanxuContract. 'identity 'library/declaration
       'contract-version "V1" 'value-contract LibraryDeclarationShape))
(def LibraryModelShape
  (.cc ObjectContract. 'identity 'library/model
       'responsibilities
       (.o
         identity: Symbol
         role: LibraryDefinitionRole
         family: Symbol
         declaration-contract: Type
         contract: Type
         parent: (yuanxu-predicate-type 'library/parent (lambda (value) (or (not value) (object? value))))
         revision: LibraryNonemptyString
         lifecycle: (List Symbol)
         rules: (List LibrarySymbolTriple)
         dependencies: (List LibrarySymbolPair)
         input-demands: (List Symbol)
         premises: (List LibraryPremiseContract)
         claims: (List LibraryClaimContract)
         limits: (List LibraryPremiseContract)
         qualification: Symbol
         assets: (List LibraryAssetContract)
         capabilities: (List Symbol)
         method-refs: (List LibraryReferenceContract))))
;; Ordinary descriptor construction, not a role registry or schema interpreter.
;; The expected descriptor comes from the source publication; submitted metadata
;; cannot select it. ObjectContract owns inherited shape and unknown-field checks.
(def (library-definition-contract identity-value role-value family-value declaration-value shape-value)
  (.o (:: expected [YuanxuContract.])
      identity: identity-value
      role: role-value
      family: family-value
      declaration-contract: declaration-value
      value-contract:
      (refine
       shape-value
       (lambda (value location)
         (if (and
              (eq? (.ref value 'role) role-value)
              (eq? (.ref value 'family) family-value)
              (eq? (.ref value 'contract) expected)
              (eq? (.ref value 'declaration-contract) declaration-value))
             '()
             (list (.o
                     kind: 'library/association-mismatch
                     path: location)))))))

;; Inert expectations are definitions, not execution receipts or issuer callbacks.
(def LibraryOptionalReference
  (yuanxu-predicate-type
   'library/optional-reference
   (lambda (v) (or (not v) (element? LibraryReferenceContract v)))))
(def LibraryMethodShape
  (.cc ObjectContract. 'identity 'library/method
       'responsibilities
       (.o
         identity: Symbol
         revision: LibraryNonemptyString
         owner: Symbol
         role: LibraryDefinitionRole
         family: Symbol
         declaration-contract: Type
         contract: Type
         kind: LibraryMethodKind
         model-ids: (List Symbol)
         policy-ids: (List Symbol)
         claims: (List Symbol)
         modes: (List Symbol)
         strength: LibraryStrength
         signature: Type
         provider: Symbol
         operation: Symbol
         result-owner: Symbol
         result-kinds: (List Symbol)
         input-demands: (List Symbol)
         assets: (List LibraryAssetContract)
         premises: (List LibraryPremiseContract)
         limits: (List LibraryPremiseContract)
         program-ref: LibraryOptionalReference
         catalog-ref: LibraryOptionalReference
         mapping-ref: LibraryOptionalReference)))
;; Concrete owners specialize definition and operation with actual expected values.
(def LibraryMethodBindingShape
  (.cc ObjectContract. 'identity 'library/method-binding
       'responsibilities (.o
                           definition: LibraryMethodShape
                           provider: Symbol
                           operation-name: Symbol
                           operation: (yuanxu-predicate-type 'library/deferred-operation procedure?)
                           current!: (yuanxu-predicate-type 'library/deferred-currentness procedure?))))

;; One native Type prototype owns normalization of the shared three-node Scope.
;; Families supply their shapes and semantic contracts; no registry or issuer.
(def (library-closed-scope? shape value)
  (and
   (element? shape value)
   (let (graph (.get value validation))
     (and
      (eq? (.get value entry) (closed-ref graph 'entry))
      (eq? (.get value declaration) (closed-ref graph 'declaration))
      (eq? (.get value config) (closed-ref graph 'config))))))
(define-type
  (LibraryScopeType. @ Type. scope-shape closed-shape entry-type declaration-type)
  .element?:
  (lambda (value)
    (if (and (object? value) (.slot? value 'validation))
        (library-closed-scope? closed-shape value)
        (element? scope-shape value)))
  .validate:
  (lambda (value)
    (if (and (object? value) (.slot? value 'validation))
        (begin (unless (library-closed-scope? closed-shape value) (raise-type-error @ value)) value)
        (let ()
          (unless (element? scope-shape value) (raise-type-error @ value))
          (unless (and
                   (eq? (.get value entry) (.get value config entry))
                   (eq? (.get value declaration) (.get value config declaration)))
            (error "Library Config associations diverged before Scope normalization"))
          (def graph
            (close-validation
             (lambda (reference)
               (def config-shape
                 (.cc ObjectContract. 'responsibilities
                      (.o
                        entry: (reference 'entry)
                        declaration: (reference 'declaration))))
               (list
                (list 'entry entry-type (.get value entry))
                (list 'declaration declaration-type (.get value declaration))
                (list 'config config-shape (.get value config))))
             3))
          (.cc value 'entry (closed-ref graph 'entry)
               'declaration (closed-ref graph 'declaration)
               'config (closed-ref graph 'config) 'validation graph)))))
