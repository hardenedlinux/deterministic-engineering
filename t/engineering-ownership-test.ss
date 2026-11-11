;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;;; -*- Gerbil -*-
(import :std/test
  (only-in :clan/poo/object .get .slot? .cc)
  (only-in :clan/poo/mop validate)
  :deterministic-engineering/init)
(export engineering-ownership-test)
(def engineering-ownership-test
  (test-suite "Engineering ownership through real native publication"
    (test-case "responsibility namespaces replace the directory-mechanism category"
      (check-equal? (.slot? deterministic-engineering.init.exports 'Modules) #f)
      (check-equal? (.slot? deterministic-engineering.init.exports 'Library) #t)
      (check-equal? (.slot? deterministic-engineering.init.exports 'Languages) #f)
      (check-equal? (file-exists? "modules") #f)
      (check-equal? (.get deterministic-engineering.init.exports Library evidence identity) 'evidence))
    (test-case "Rust consumes the actual generic parent without a copied model"
      (def parent (.get deterministic-engineering.init.exports Library backpressure-memory entry))
      (def rust (.get deterministic-engineering.init.exports Library rust-resources))
      (check-equal? (eq? (.get rust entry parent) parent) #t)
      (check-equal?
        (eq? (.get rust model-library)
             (.get deterministic-engineering.init.exports Library backpressure-tokio-rayon)) #t)
      (check-equal? (eq? (.get rust model-library parent entry) parent) #t)
      (def model-library (.get rust model-library))
      (check-equal? (eq? (.get rust config coding-policy)
                        (.get model-library config coding-policy)) #t)
      (check-equal? (eq? (.get rust policies design)
                        (.get model-library config design-policy)) #t)
      (check-equal?
        (eq? (validate (.get model-library contracts scope value-contract) model-library) model-library) #t)
      (check-equal?
        (eq? (validate (.get model-library contracts scope value-contract) model-library) model-library) #t)
      (check-exception
        (validate (.get model-library contracts scope value-contract)
          (.cc model-library 'config (.cc (.get model-library config) 'purpose 'wrong))) error?)
      (check-equal? (.get rust entry identity) 'rust.resources.backpressure-memory)
      (check-equal? (file-exists?
        "languages-engineering/rust/concurrency/resource-control/backpressure-memory/Cargo.lock") #t))
    (test-case "Rust project contains target-language sources while Scheme owns its driver"
      (def crate "languages-engineering/rust/concurrency/resource-control/backpressure-memory")
      (def (scheme-free? directory)
        (andmap
          (lambda (name)
            (def path (path-expand name directory))
            (if (eq? (file-info-type (file-info path #f)) 'directory)
                (scheme-free? path)
                (not (member (path-extension path) '(".ss" ".scm" ".sld")))))
          (directory-files directory)))
      (check-equal? (scheme-free? crate) #t)
      (check-equal? (file-exists? (path-expand "src/main.rs" crate)) #t)
      (check-equal? (file-exists? (path-expand "Cargo.toml" crate)) #t)
      (check-equal? (file-exists? "library/rust-resources/interface.ss") #t)
      (check-equal? (file-exists? "library/backpressure-tokio-rayon/ownership.sysml") #t))))
