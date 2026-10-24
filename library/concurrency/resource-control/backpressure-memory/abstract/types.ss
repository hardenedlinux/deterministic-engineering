;;; Generic family Types consume neutral Library Types, never child objects.
(import :clan/poo/object
        (only-in :clan/poo/mop Type Type. define-type validate element? raise-type-error)
        (only-in :clan/poo/recursive-validation close-validation closed? closed-ref)
        (only-in :clan/poo/object-contract ObjectContract. refine)
        (only-in :yuanxu/object-types/contracts YuanxuContract. yuanxu-predicate-type)
        "../../../../../types.ss")
(export BackpressureDeclarationContract BackpressureModelContract
        BackpressureConfigContract BackpressureScopeContract backpressure-model?)
(def family 'concurrency.resource-control.backpressure-memory)
(def BackpressureDeclarationContract
 (.cc LibraryDeclarationContract 'identity 'backpressure-memory/declaration
  'value-contract (refine LibraryDeclarationShape
    (lambda (value location)
     (if (eq? (.get value family) family) '()
       (list (.o kind: 'backpressure/family-mismatch path: location)))))))
(def BackpressureModelContract
 (library-definition-contract 'backpressure-memory/model 'generic-model family
  BackpressureDeclarationContract
  (refine LibraryModelShape
   (lambda (value location)
    (if (and (not (.get value parent))
             (eq? (.get value identity) family)) '()
      (list (.o kind: 'backpressure/generic-parent-or-identity path: location)))))))
(def (backpressure-model? value)
 (element? (.get BackpressureModelContract value-contract) value))
(def BackpressureConfigContract
 (.cc YuanxuContract. 'identity 'backpressure-memory/config
  'value-contract (.cc ObjectContract. 'responsibilities
    (.o entry: (.get BackpressureModelContract value-contract)
        declaration: (.get BackpressureDeclarationContract value-contract)))))
(def ScopeShape
  (.cc ObjectContract. 'responsibilities
    (.o config: (.get BackpressureConfigContract value-contract)
        declaration: (.get BackpressureDeclarationContract value-contract)
        entry: (.get BackpressureModelContract value-contract)
        contracts: (.cc ObjectContract. 'responsibilities
          (.o model: (yuanxu-predicate-type 'backpressure-memory/model-contract
                       (lambda (value) (eq? value BackpressureModelContract)))
              declaration: (yuanxu-predicate-type 'backpressure-memory/declaration-contract
                       (lambda (value) (eq? value BackpressureDeclarationContract)))
              config: (yuanxu-predicate-type 'backpressure-memory/config-contract
                       (lambda (value) (eq? value BackpressureConfigContract))))))))

(def ClosedScopeShape
 (.cc ScopeShape 'responsibilities
  (.+ (.get ScopeShape responsibilities)
   (.o validation: (yuanxu-predicate-type 'library/value-closure closed?)))))
(def (closed-scope? value)
 (and (element? ClosedScopeShape value)
      (let (graph (.get value validation))
       (and (eq? (.get value entry) (closed-ref graph 'entry))
            (eq? (.get value declaration) (closed-ref graph 'declaration))
            (eq? (.get value config) (closed-ref graph 'config))))))
(define-type (BackpressureScopeType @ Type.)
 .element?: (lambda (value)
   (if (and (object? value) (.slot? value 'validation))
     (closed-scope? value) (element? ScopeShape value)))
 .validate: (lambda (value)
  (if (and (object? value) (.slot? value 'validation))
   (begin (unless (closed-scope? value) (raise-type-error @ value)) value)
   (let ()
    (unless (element? ScopeShape value) (raise-type-error @ value))
    (unless (and (eq? (.get value entry) (.get value config entry))
                 (eq? (.get value declaration) (.get value config declaration)))
      (error "Library Config associations diverged before Scope normalization"))
    ;; One finite native value closure owns shared normalized children. It is
    ;; not a Library registry, source issuer or another module linker.
    (def graph
     (close-validation
      (lambda (reference)
       (def config-shape (.cc ObjectContract. 'responsibilities
           (.o entry: (reference 'entry) declaration: (reference 'declaration))))
       (list (list 'entry (.get BackpressureModelContract value-contract) (.get value entry))
             (list 'declaration (.get BackpressureDeclarationContract value-contract) (.get value declaration))
             (list 'config config-shape (.get value config)))) 3))
    (.cc value 'entry (closed-ref graph 'entry)
         'declaration (closed-ref graph 'declaration)
         'config (closed-ref graph 'config) 'validation graph)))))
(def BackpressureScopeContract
 (.cc YuanxuContract. 'identity 'backpressure-memory/scope 'value-contract BackpressureScopeType))
