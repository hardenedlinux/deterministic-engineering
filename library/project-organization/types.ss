;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Organization family consumes neutral Library declarations and native Contracts.
(import
  :clan/poo/object
  (only-in :clan/poo/mop Any Function Type define-type element?)
  (only-in :clan/poo/type String Symbol List)
  (only-in :clan/poo/recursive-validation closed?)
  (only-in :clan/poo/object-contract ObjectContract. refine)
  (only-in :yuanxu/object-types/contracts YuanxuContract. yuanxu-predicate-type)
  "../../types.ss")
(export
  OrganizationDeclarationContract
  OrganizationModelContract
  OrganizationConfigContract
  OrganizationScopeContract
  OrganizationCatalogContract
  OrganizationMappingContract
  OrganizationMethodRequirements
  OrganizationMethodContract
  OrganizationMethodsShape
  OrganizationReasonSignature
  OrganizationRenderSignature)
(def family 'project-organization)
(def (unique? values)
  (or (null? values) (and (not (member (car values) (cdr values))) (unique? (cdr values)))))
(def (text-row count)
  (yuanxu-predicate-type
   'organization/text-row
   (lambda (row)
     (and
      (list? row)
      (= (length row) count)
      (andmap (lambda (v) (and (string? v) (not (string-empty? v)))) row)))))
(def OrganizationDeclarationContract
  (.cc LibraryDeclarationContract 'identity 'project-organization/declaration
       'value-contract (refine
                        LibraryDeclarationShape
                        (lambda (value location)
                          (if (eq? (.get value family) family)
                              '()
                              (list (.o kind: 'organization/family path: location)))))))
(def DefinitionShape
  (.cc ObjectContract. 'responsibilities
       (.o
         identity: Symbol
         revision: LibraryNonemptyString
         owner: Symbol
         role: LibraryDefinitionRole
         family: Symbol
         declaration-contract: Type
         contract: Type)))
(def OrganizationCatalogContract
  (library-definition-contract
   'project-organization/catalog
   'catalog
   family
   OrganizationDeclarationContract
   (.cc DefinitionShape 'responsibilities
        (.+
         (.get DefinitionShape responsibilities)
         (.o
           asset: LibraryAssetContract
           package: Symbol
           definitions: (List LibraryNonemptyString))))))
(def OrganizationMappingContract
  (library-definition-contract
   'project-organization/mapping
   'mapping
   family
   OrganizationDeclarationContract
   (.cc DefinitionShape 'responsibilities
        (.+
         (.get DefinitionShape responsibilities)
         (.o
           catalog-id: Symbol
           roles: (List (text-row 2))
           loss: LibraryNonemptyString)))))
(def OrganizationReasonSignature (Function (list Any) (list Any)))
(def OrganizationRenderSignature (Function (list String) (list Any)))
;; Finite operation requirements belong to the published method Contract.
(def OrganizationMethodRequirements
  (.o
    reason: (.o
              kind: 'application-reasoning
              signature: OrganizationReasonSignature)
    render: (.o
              kind: 'model-projection
              signature: OrganizationRenderSignature)))
(def OrganizationMethodContract
  (library-definition-contract
   'project-organization/method
   'method
   family
   OrganizationDeclarationContract
   (refine
    LibraryMethodShape
    (lambda (v location)
      (def operation-name (.get v operation))
      (def expected
        (and
         (.slot? OrganizationMethodRequirements operation-name)
         (.ref OrganizationMethodRequirements operation-name)))
      (if (and
           (eq? (.get v provider) 'project-formation)
           (eq? (.get v result-owner) 'project-formation)
           (equal? (.get v model-ids) '(project-organization))
           (equal? (.get v modes) '(design-only))
           (eq? (.get v strength) 'authored-conditional)
           expected
           (eq? (.get v kind) (.get expected kind))
           (eq? (.get v signature) (.get expected signature)))
          '()
          (list (.o kind: 'organization/method-operation-or-strength path: location)))))))
(def OrganizationMethodsShape
  (.cc ObjectContract. 'responsibilities
       (.o
         reason: (.get OrganizationMethodContract value-contract)
         render: (.get OrganizationMethodContract value-contract))))
(def (reference-matches? reference-value target)
  (and
   reference-value
   (eq? (.get reference-value identity) (.get target identity))
   (equal? (.get reference-value revision) (.get target revision))
   (eq? (.get reference-value owner) (.get target owner))))
(def OrganizationModelContract
  (library-definition-contract
   'project-organization/model
   'organization
   family
   OrganizationDeclarationContract
   (refine
    (.cc LibraryModelShape 'responsibilities
         (.+
          (.get LibraryModelShape responsibilities)
          (.o
            roles: (List (text-row 3))
            owner-kinds: (List (text-row 2))
            protected: (List (text-row 2))
            products: (List LibraryNonemptyString)
            duties: (List LibraryNonemptyString)
            required-capabilities: (List LibraryNonemptyString)
            methods: OrganizationMethodsShape
            catalog: (.get OrganizationCatalogContract value-contract)
            mapping: (.get OrganizationMappingContract value-contract))))
    (lambda (value location)
      (def roles (.get value roles))
      (def catalog (.get value catalog))
      (def mapping (.get value mapping))
      (if (and
           (not (.get value parent))
           (eq? (.get value identity) family)
           (pair? roles)
           (unique? (map car roles))
           (unique? (map car (.get value owner-kinds)))
           (pair? (.get value products))
           (unique? (.get value products))
           (pair? (.get value duties))
           (unique? (.get value duties))
           (pair? (.get value required-capabilities))
           (unique? (.get value required-capabilities))
           (andmap (lambda (row) (member (cdr row) (.get value owner-kinds))) roles)
           (andmap
            (lambda (row)
              (let (role (assoc (car row) roles))
                (and role (equal? (cadr row) (cadr role)))))
            (.get value protected))
           (andmap
            (lambda (key)
              (def method (.ref (.get value methods) key))
              (and
               (eq? (.get method operation) key)
               (pair? (.get method claims))
               (andmap
                (lambda (claim-id) (find (lambda (claim) (eq? claim-id (.get claim identity))) (.get value claims)))
                (.get method claims))
               (find (cut reference-matches? <> method) (.get value method-refs))
               (reference-matches? (.get method catalog-ref) catalog)
               (reference-matches? (.get method mapping-ref) mapping)))
            '(reason render))
           (= (length (.get value method-refs)) 2)
           (unique? (map (cut .get <> identity) (.get value method-refs)))
           (eq? (.get mapping catalog-id) (.get catalog identity))
           (equal? (map car (.get mapping roles)) (map car roles))
           (andmap (lambda (row) (member (cadr row) (.get catalog definitions))) (.get mapping roles))
           (find
            (lambda (asset)
              (and
               (eq? (.get asset identity) (.get catalog asset identity))
               (equal? (.get asset relative-path) (.get catalog asset relative-path))))
            (.get value assets)))
          '()
          (list (.o kind: 'organization/demand-or-catalog-closure path: location)))))))
(def OrganizationConfigContract
  (.cc YuanxuContract. 'identity 'project-organization/config
       'value-contract (.cc ObjectContract. 'responsibilities
                            (.o
                              entry: (.get OrganizationModelContract value-contract)
                              declaration: (.get OrganizationDeclarationContract value-contract)))))
(def ScopeShape
  (.cc ObjectContract. 'responsibilities
       (.o
         config: (.get OrganizationConfigContract value-contract)
         declaration: (.get OrganizationDeclarationContract value-contract)
         entry: (.get OrganizationModelContract value-contract)
         contracts: (.cc ObjectContract. 'responsibilities
                         (.o
                           model: (yuanxu-predicate-type
                                   'project-organization/model-contract
                                   (lambda (value) (eq? value OrganizationModelContract)))
                           declaration: (yuanxu-predicate-type
                                         'project-organization/declaration-contract
                                         (lambda (value) (eq? value OrganizationDeclarationContract)))
                           config: (yuanxu-predicate-type
                                    'project-organization/config-contract
                                    (lambda (value) (eq? value OrganizationConfigContract))))))))

(def ClosedScopeShape
  (.cc ScopeShape 'responsibilities
       (.+
        (.get ScopeShape responsibilities)
        (.o
          validation: (yuanxu-predicate-type 'library/value-closure closed?)))))
(define-type
  (OrganizationScopeType @ LibraryScopeType.)
  scope-shape:
  ScopeShape
  closed-shape:
  ClosedScopeShape
  entry-type:
  (.get OrganizationModelContract value-contract)
  declaration-type:
  (.get OrganizationDeclarationContract value-contract))
(def OrganizationScopeContract
  (.cc YuanxuContract. 'identity 'project-organization/scope 'value-contract OrganizationScopeType))
