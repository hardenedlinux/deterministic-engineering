;;; -*- Gerbil -*-
(import :std/test :clan/poo/object :deterministic-engineering/init
        :deterministic-engineering/profiles/resource-lifecycle
        (only-in :std/io/tempfile call-with-temporary-directory)
        (only-in :std/misc/ports read-all-as-string))
(export native-context-test)
(def native-context-test
  (test-suite "One source-bound native capture at Scenario admission"
    (test-case "source/Profile mutation and split scope forgery cannot reuse the captured snapshot"
      (def root (current-directory))
      (def scene (.get init.Scenarios resource-lifecycle scope))
      (def methods (.ref scene 'methods))
      (def original (path-expand "library/concurrency/resource-control/backpressure-memory/rust/native" root))
      (call-with-temporary-directory "native-context"
        (lambda (crate)
          (create-directory (path-expand "src" crate))
          (for-each (lambda (name) (copy-file (path-expand name original) (path-expand name crate)))
            '("Cargo.toml" "Cargo.lock" "src/main.rs"))
          (def context ((.ref scene 'capture) root LifecycleProfile crate
            (getenv "RESOURCE_CARGO") (getenv "RESOURCE_RUSTC") 'context-test))
          (check-equal? (eq? ((.ref methods 'context-current!) context) context) #t)
          (check-equal? (object? ((.ref scene 'open-review) context)) #t)
          (check-exception ((.ref scene 'open-review) (.cc context 'profile LargerPayloadProfile)) (lambda (_) #t))
          (check-exception ((.ref scene 'open-review) (.cc context 'profile
            (.cc LifecycleProfile 'factors (cons 'cache (.ref LifecycleProfile 'factors)))) ) (lambda (_) #t))
          (check-exception ((.ref scene 'open-review) (.cc context 'scopes
            (cons (car (.ref context 'scopes)) (cdr (cdr (.ref context 'scopes)))))) (lambda (_) #t))
          (def source (path-expand "src/main.rs" crate))
          (def text (call-with-input-file source read-all-as-string))
          (call-with-output-file (list path: source truncate: #t)
            (lambda (p) (display text p) (display "\n// Changed bytes, unchanged intended protocol.\n" p)))
          (check-exception ((.ref scene 'open-review) context) (lambda (_) #t))
          (def revised ((.ref scene 'capture) root LifecycleProfile crate
            (getenv "RESOURCE_CARGO") (getenv "RESOURCE_RUSTC") 'context-test))
          (check-equal? (equal? (.ref revised 'snapshot) (.ref context 'snapshot)) #f)
          (check-equal? (object? ((.ref scene 'open-review) revised)) #t))))))
