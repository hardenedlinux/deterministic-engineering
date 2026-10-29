;;; -*- Gerbil -*-
(import :std/test
  (only-in :clan/poo/object .get .slot?)
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
      (def parent (.get deterministic-engineering.init.exports Library backpressure-memory scope entry))
      (def rust (.get deterministic-engineering.init.exports Library rust-resources scope))
      (check-equal? (eq? (.get rust entry parent) parent) #t)
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
      (check-equal? (file-exists? "library/drivers/rust-resources/interface.ss") #t)
      (check-equal? (file-exists? "library/drivers/rust-resources/ownership.sysml") #t))))
