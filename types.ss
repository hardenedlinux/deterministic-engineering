;;; Shared Library declaration vocabulary. Types only: no objects, IO or Engine.
(import :clan/poo/object
        (only-in :clan/poo/mop Type element?)
        (only-in :clan/poo/type Symbol String List)
        (only-in :clan/poo/object-contract ObjectContract. refine)
        (only-in :yuanxu/types YuanxuContract. yuanxu-predicate-type))
(export LibraryDeclarationContract LibraryDeclarationShape LibraryReferenceContract
        LibraryAssetContract LibraryPremiseContract LibraryClaimContract
        LibraryMethodShape LibraryMethodBindingShape LibraryModelShape LibraryMethodKind LibraryDefinitionRole LibraryStrength
        LibraryNonemptyString LibrarySymbolPair LibrarySymbolTriple
        library-definition-contract)
(def LibraryNonemptyString
 (yuanxu-predicate-type 'library/nonempty-string
  (lambda (value) (and (string? value) (> (string-length value) 0)))))
(def (symbols-of-length count)
 (yuanxu-predicate-type 'library/symbol-row
  (lambda (value) (and (list? value) (= (length value) count) (andmap symbol? value)))))
(def LibrarySymbolPair (symbols-of-length 2))
(def LibrarySymbolTriple (symbols-of-length 3))
(def (finite-type identity-values choices)
 (yuanxu-predicate-type identity-values (lambda (value) (and (memq value choices) #t))))
(def LibraryDefinitionRole
 (finite-type 'library/definition-role '(generic-model specialization integration organization policy method catalog mapping)))
(def LibraryMethodKind
 (finite-type 'library/method-kind '(application-reasoning model-projection content-observation implementation-execution model-verification theorem-check)))
(def LibraryStrength
 (finite-type 'library/strength '(authored-conditional finite-model arithmetic execution language-validation correspondence research-hypothesis)))
(def LibraryReferenceContract
 (.cc ObjectContract. 'identity 'library/reference
  'responsibilities (.o identity: Symbol revision: LibraryNonemptyString owner: Symbol)))
(def LibraryAssetContract
 (.cc ObjectContract. 'identity 'library/asset
  'responsibilities (.o identity: Symbol revision: LibraryNonemptyString owner: Symbol
   kind: (finite-type 'library/asset-kind '(scheme quint lean rust sysml org mapping))
   relative-path: LibraryNonemptyString)))
(def LibraryPremiseContract
 (.cc ObjectContract. 'identity 'library/premise
  'responsibilities (.o identity: Symbol statement: LibraryNonemptyString inputs: (List Symbol))))
(def LibraryClaimContract
 (.cc ObjectContract. 'identity 'library/claim
  'responsibilities (.o identity: Symbol meaning: LibraryNonemptyString
   premises: (List Symbol) duties: (List Symbol) strength: LibraryStrength)))
(def LibraryDeclarationShape
 (.cc ObjectContract. 'identity 'library/declaration
  'responsibilities (.o identity: Symbol family: Symbol source-owner: Symbol
   applicability: (List Symbol) role-contracts: (List Type) extension-expectations: (List Symbol))))
;; The sole authored Library contract generation. Family declarations inherit it;
;; definitions, Scope values, Profiles, Scenarios and views carry references.
(def LibraryDeclarationContract
 (.cc YuanxuContract. 'identity 'library/declaration
  'contract-version "V1" 'value-contract LibraryDeclarationShape))
(def LibraryModelShape
 (.cc ObjectContract. 'identity 'library/model
  'responsibilities
  (.o identity: Symbol role: LibraryDefinitionRole family: Symbol
   declaration-contract: Type contract: Type
   parent: (yuanxu-predicate-type 'library/parent (lambda (value) (or (not value) (object? value))))
   revision: LibraryNonemptyString lifecycle: (List Symbol)
   rules: (List LibrarySymbolTriple) dependencies: (List LibrarySymbolPair)
   input-demands: (List Symbol) premises: (List LibraryPremiseContract)
   claims: (List LibraryClaimContract) limits: (List LibraryPremiseContract) qualification: Symbol assets: (List LibraryAssetContract)
   capabilities: (List Symbol) method-refs: (List LibraryReferenceContract))))
;; Ordinary descriptor construction, not a role registry or schema interpreter.
;; The expected descriptor comes from the source publication; submitted metadata
;; cannot select it. ObjectContract owns inherited shape and unknown-field checks.
(def (library-definition-contract identity-value role-value family-value declaration-value shape-value)
 (.o (:: expected [YuanxuContract.])
  identity: identity-value role: role-value family: family-value
  declaration-contract: declaration-value
  value-contract:
  (refine shape-value
   (lambda (value location)
    (if (and (eq? (.ref value 'role) role-value)
             (eq? (.ref value 'family) family-value)
             (eq? (.ref value 'contract) expected)
             (eq? (.ref value 'declaration-contract) declaration-value))
      '() (list (.o kind: 'library/association-mismatch path: location)))))))

;; Inert expectations are definitions, not execution receipts or issuer callbacks.
(def LibraryOptionalReference
 (yuanxu-predicate-type 'library/optional-reference
  (lambda (v) (or (not v) (element? LibraryReferenceContract v)))))
(def LibraryMethodShape
 (.cc ObjectContract. 'identity 'library/method
  'responsibilities
  (.o identity: Symbol revision: LibraryNonemptyString owner: Symbol
      role: LibraryDefinitionRole family: Symbol declaration-contract: Type contract: Type
      kind: LibraryMethodKind model-ids: (List Symbol) policy-ids: (List Symbol)
      claims: (List Symbol) modes: (List Symbol) strength: LibraryStrength signature: Type
      provider: Symbol operation: Symbol result-owner: Symbol result-kinds: (List Symbol)
      input-demands: (List Symbol) assets: (List LibraryAssetContract)
      premises: (List LibraryPremiseContract) limits: (List LibraryPremiseContract)
      program-ref: LibraryOptionalReference catalog-ref: LibraryOptionalReference mapping-ref: LibraryOptionalReference)))
;; Concrete owners specialize definition and operation with actual expected values.
(def LibraryMethodBindingShape
 (.cc ObjectContract. 'identity 'library/method-binding
  'responsibilities (.o definition: LibraryMethodShape provider: Symbol operation-name: Symbol
   operation: (yuanxu-predicate-type 'library/deferred-operation procedure?)
   current!: (yuanxu-predicate-type 'library/deferred-currentness procedure?))))
