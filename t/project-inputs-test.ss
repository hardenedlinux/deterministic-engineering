;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
(import :std/test :clan/poo/object
 (only-in :std/io/tempfile call-with-temporary-directory)
 "../library/project-formation/inputs.ss")
(export project-inputs-test)
(def (put path text)
 (call-with-output-file (list path: path truncate: #t) (cut display text <>)))
(def project-inputs-test
 (test-suite "Actual repository acquisition remains distinct from final C"
  (test-case "real bytes, separate occurrences, documentary copies and original-byte repair"
   (call-with-temporary-directory "project-inputs"
    (lambda (root)
     (def path (path-expand "input.org" root)) (put path "actual repository content")
     (def acquired (formation-acquire-inputs root '("input.org") 1024 60))
     (def other (formation-acquire-inputs root '("input.org") 1024 60))
     (check-equal? (eq? acquired other) #f)
     (def observed (formation-input-observation acquired))
     (check-equal? (.get observed status) 'repository-observation)
     (check-equal? (cadar (.get observed inputs)) "actual repository content")
     (check-exception (formation-inputs-current! observed) error?)
     (put path "changed")
     (check-exception (formation-inputs-current! acquired) error?)
     (put path "actual repository content")
     (check-equal? (eq? (formation-inputs-current! acquired) acquired) #t))))
  (test-case "missing, escape, duplicate, oversized and nonpositive lifetime requests refuse"
   (call-with-temporary-directory "project-input-refusals"
    (lambda (root)
     (put (path-expand "input.org" root) "actual")
     (for-each (lambda (paths)
       (check-exception (formation-acquire-inputs root paths 1024 60) error?))
       '(("missing.org") ("../input.org") ("/input.org") ("input.org" "input.org")))
     (check-exception (formation-acquire-inputs root '("input.org") 1 60) error?)
     (check-exception (formation-acquire-inputs root '("input.org") 1024 0) error?))))
  (test-case "elapsed lifetime refuses even when the bytes remain identical"
   (call-with-temporary-directory "project-input-expiry"
    (lambda (root)
     (put (path-expand "input.org" root) "actual")
     (def acquired (formation-acquire-inputs root '("input.org") 1024 0.05))
     (thread-sleep! 0.08)
     (check-exception (formation-inputs-current! acquired) error?))))))
