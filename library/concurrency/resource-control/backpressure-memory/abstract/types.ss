;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-only

;;; Generic family Types consume neutral Library Types, never child objects.
(import
  :clan/poo/object
  (only-in :clan/poo/mop Type define-type element?)
  (only-in :clan/poo/type List)
  (only-in :clan/poo/recursive-validation closed?)
  (only-in :clan/poo/object-contract ObjectContract. refine)
  (only-in :yuanxu/object-types/contracts YuanxuContract. yuanxu-predicate-type)
  "../../../../../types.ss")
(export
  BackpressureDeclarationContract
  BackpressureModelContract
  BackpressureModelShape
  BackpressureConfigContract
  BackpressureScopeContract
  backpressure-model?)
(def family 'concurrency.resource-control.backpressure-memory)
(def BackpressureDeclarationContract
  (.cc LibraryDeclarationContract 'identity 'backpressure-memory/declaration
       'value-contract (refine
                        LibraryDeclarationShape
                        (lambda (value location)
                          (if (eq? (.get value family) family)
                              '()
                              (list
                               (.o
                                 kind: 'backpressure/family-mismatch
                                 path: location)))))))
(def BackpressureModelShape
  (.cc LibraryModelShape 'responsibilities
    (.+ (.get LibraryModelShape responsibilities)
        (.o factor-implications: (List LibrarySymbolTriple)))))
(def BackpressureModelContract
  (library-definition-contract
   'backpressure-memory/model
   'generic-model
   family
   BackpressureDeclarationContract
   (refine
    BackpressureModelShape
    (lambda (value location)
      (if (and (not (.get value parent)) (eq? (.get value identity) family))
          '()
          (list (.o kind: 'backpressure/generic-parent-or-identity path: location)))))))
(def (backpressure-model? value)
  (element? (.get BackpressureModelContract value-contract) value))
(def BackpressureConfigContract
  (.cc YuanxuContract. 'identity 'backpressure-memory/config
       'value-contract (.cc ObjectContract. 'responsibilities
                            (.o
                              entry: (.get BackpressureModelContract value-contract)
                              declaration: (.get BackpressureDeclarationContract value-contract)))))
(def ScopeShape
  (.cc ObjectContract. 'responsibilities
       (.o
         config: (.get BackpressureConfigContract value-contract)
         declaration: (.get BackpressureDeclarationContract value-contract)
         entry: (.get BackpressureModelContract value-contract)
         contracts: (.cc ObjectContract. 'responsibilities
                         (.o
                           model: (yuanxu-predicate-type
                                   'backpressure-memory/model-contract
                                   (lambda (value) (eq? value BackpressureModelContract)))
                           declaration: (yuanxu-predicate-type
                                         'backpressure-memory/declaration-contract
                                         (lambda (value) (eq? value BackpressureDeclarationContract)))
                           config: (yuanxu-predicate-type
                                    'backpressure-memory/config-contract
                                    (lambda (value) (eq? value BackpressureConfigContract))))))))

(def ClosedScopeShape
  (.cc ScopeShape 'responsibilities
       (.+
        (.get ScopeShape responsibilities)
        (.o
          validation: (yuanxu-predicate-type 'library/value-closure closed?)))))
(define-type
  (BackpressureScopeType @ LibraryScopeType.)
  scope-shape:
  ScopeShape
  closed-shape:
  ClosedScopeShape
  entry-type:
  (.get BackpressureModelContract value-contract)
  declaration-type:
  (.get BackpressureDeclarationContract value-contract))
(def BackpressureScopeContract
  (.cc YuanxuContract. 'identity 'backpressure-memory/scope 'value-contract BackpressureScopeType))
