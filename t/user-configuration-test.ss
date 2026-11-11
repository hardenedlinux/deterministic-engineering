;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :std/test
        :clan/poo/object
        (only-in :std/source this-source-file)
        (only-in :yuanxu/module-system/source/init module-init-intent))
(export user-configuration-test)

(def root (path-expand ".." (path-directory (this-source-file))))
(def (example-intent name)
  (def path (path-expand (string-append "examples/" name ".ss") root))
  (module-init-intent (call-with-input-file path read-all) path))
(def (decisions intent disabled?)
  (map (cut .get <> identity)
    (filter (lambda (row) (eq? (.get row disabled?) disabled?))
            (.get intent decisions))))

(def user-configuration-test
  (test-suite "Actual user declarations through native Yuanxu"
    (test-case "C/C++ example selects assurance declarations and excludes application cases"
      (def intent (example-intent "source-contracts"))
      (check-equal? (decisions intent #f)
                    '(source-contract-profiles bounded-capacity resource-lifetime evidence))
      (check-equal? (decisions intent #t)
                    '(backpressure-tokio-rayon gateway-profiles))
      (check-equal? (map (cut .get <> mount) (.get intent windows)) '(Library))
      (check-equal? (andmap (cut .get <> disable-specified?) (.get intent decisions)) #t))
    (test-case "Rust example has a different explicit selection over the same Library"
      (def intent (example-intent "rust-backpressure"))
      (check-equal? (decisions intent #f) '(backpressure-tokio-rayon evidence))
      (check-equal? (decisions intent #t) '(source-contract-profiles gateway-profiles)))
    (test-case "computed enable decisions are refused instead of evaluated"
      (check-exception
        (module-init-intent
          '((yuanxu! mode: explicit
              (source-contracts disable: (error "must not execute"))))
          "init.ss")
        error?))))
