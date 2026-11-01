;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-only

;;; -*- Gerbil -*-
(import :std/test :clan/poo/object
        (only-in :std/source this-source-file)
        (only-in :std/io/tempfile call-with-temporary-directory)
        (only-in :yuanxu/module-system/interface yuanxu-load-modules))
(export library-selection-test)
(import (only-in :clan/poo/mop validate)
        (only-in "../library/drivers/rust-resources/types.ss" RustResourcesScopeContract RustResourceModelContract))
(def repo-root (path-expand ".." (path-directory (this-source-file))))
(def (write-source path text)
  (call-with-output-file (list path: path truncate: #t) (cut display text <>)))
(def library-selection-test
  (test-suite "Core selection confines domain Library admission"
    (test-case "a parent-only selection leaves an invalid unrelated owner cold"
      (def parent (path-expand "library/concurrency/resource-control/backpressure-memory/abstract" repo-root))
      (call-with-temporary-directory "library-selection"
        (lambda (root)
          (write-source (path-expand "gerbil.pkg" root) "(package: library-selection-canary)")
          (create-directory (path-expand "library" root))
          (create-directory (path-expand "poison" root))
          (write-source (path-expand "poison/interface.ss" root) "(((invalid-canary")
          (def path (path-expand "init.ss" root))
          (write-source path (string-append "(yuanxu! source: " (object->string (path-expand "library" repo-root)) " mode: explicit (backpressure-memory @ "
            (object->string parent) ") (poison @ \"./poison\" disable: #t))"))
          (def view (yuanxu-load-modules path))
          (check-equal? (.get view dependency-order) '(backpressure-memory))
          (check-equal? (.get view modules backpressure-memory entry identity)
            'concurrency.resource-control.backpressure-memory)
          (def scope (.get view modules backpressure-memory))
          (check-equal? (.get scope contracts model declaration-contract contract-version) "V1")
          (check-equal? (eq? (.get scope entry) (.get scope config entry)) #t)
          (check-equal? (.slot? (.get scope entry) 'contract-version) #f)
          ;; Force build projection as well as scope demand.
          (.get view build-graph)
          (check-equal? (.slot? (.get view modules) 'rust-resources) #f)
          (write-source path "(yuanxu! mode: explicit (poison @ \"./poison\"))")
          (check-exception (.get (yuanxu-load-modules path) selected-graph) (lambda (_) #t)))))
    (test-case "selected Rust Scope retains external SD and canonical policies and integration"
     (def base (path-expand "library/concurrency/resource-control/backpressure-memory" repo-root))
     (call-with-temporary-directory "rust-library-selection"
      (lambda (root)
       (write-source (path-expand "gerbil.pkg" root) "(package: rust-library-selection-canary)")
       (create-directory (path-expand "library" root))
       (def path (path-expand "init.ss" root))
       (write-source path (string-append "(yuanxu! source: " (object->string (path-expand "library" repo-root)) " mode: explicit (backpressure-memory @ "
         (object->string (path-expand "abstract" base)) ") (backpressure-tokio-rayon @ "
         (object->string (path-expand "tokio-rayon" base)) ") (rust-resources @ "
         (object->string (path-expand "library/drivers/rust-resources" repo-root)) "))"))
       (def view (yuanxu-load-modules path))
       (def parent (.get view modules backpressure-memory))
       (def scope (.get view modules rust-resources))
       (check-equal? (eq? (.get scope parent) parent) #t)
       (check-equal? (eq? (.get scope entry parent) (.get parent entry)) #t)
       (check-equal? (eq? (.get scope integration-entry parent) (.get scope entry)) #t)
       (check-equal? (eq? (.get scope config coding-policy) (.get scope policies coding)) #t)
       (check-equal? (eq? (.get scope config design-policy) (.get scope policies design)) #t)
       (check-equal? (.get scope contracts model declaration-contract contract-version) "V1")
       ;; The expected Contract is the actual selected publication's binding.
       ;; A direct file import is another owner Context, not that publication.
       (def expected (.get scope contracts scope value-contract))
       (check-equal? (eq? (validate expected scope) scope) #t)
       (check-equal? (eq? (.get scope contracts model) RustResourceModelContract) #f)
       (check-exception (validate (.get RustResourcesScopeContract value-contract) scope) error?)
       (check-exception (validate expected
         (.cc scope 'integration-entry (.cc (.get scope integration-entry) 'parent (.get parent entry)))) error?)
       (check-exception (validate expected
         (.cc scope 'policies (.cc (.get scope policies) 'coding (.get scope policies design)))) error?)
       (check-equal? (procedure? (.get scope methods register)) #t)
       (for-each (lambda (key)
        (def binding (.ref (.get scope bound-methods bindings) key))
        (check-equal? (eq? (.get binding operation) (.ref (.get scope methods) key)) #t)
        (check-equal? (eq? (.get binding definition) (.ref (.get scope bound-methods definitions) key)) #t))
        '(native quint lean integration))
       (check-exception (validate expected (.cc scope 'methods (.cc (.get scope methods) 'native (lambda args 'forged)))) error?)
       (check-exception (validate expected (.cc scope 'bound-methods (.cc (.get scope bound-methods) 'operations (.cc (.get scope methods) 'native (lambda args 'forged))))) error?)
       (def definitions (.get scope bound-methods definitions))
       (def bindings (.get scope bound-methods bindings))
       (def (replace-native metadata)
        (.cc scope 'bound-methods (.cc (.get scope bound-methods)
          'definitions (.cc definitions 'native metadata)
          'bindings (.cc bindings 'native (.cc (.get bindings native) 'definition metadata)))))
       (check-exception (validate expected (replace-native
         (.cc (.get definitions native) 'model-ids '(foreign-model)))) error?)
       (check-exception (validate expected (replace-native
         (.cc (.get definitions native) 'claims '(foreign-obligation)))) error?)
       (.get view build-graph))))))
