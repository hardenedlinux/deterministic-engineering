;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; -*- Gerbil -*-
(import
  :std/test
  :clan/poo/object
  :deterministic-engineering/init
  :deterministic-engineering/profiles/resource-lifecycle
  (only-in :std/io/tempfile call-with-temporary-directory)
  (only-in :std/misc/ports read-all-as-string)
  (only-in :clan/poo/mop validate TypeError?)
  (only-in :gerbil-ascent/program/session gerbil-ascent-session-run)
  (only-in "../scenarios/resource-lifecycle/func.ss" resource-lifecycle-scope))
(export
  native-context-test)
(def (scope-basis context kind)
  (cadr (assq kind (map cdr (.ref context 'scopes)))))
(def (stale-source-context? cause)
  (and
   (string-contains
    (call-with-output-string (lambda (output) (display-exception cause output)))
    "native context no longer matches selected source/Profile/tools")
   #t))

(def native-context-test
  (test-suite "One source-bound native capture at Scenario admission"
    (test-case "source/Profile mutation and split scope forgery cannot reuse the captured snapshot"
      (def root (current-directory))
      (def scene (.get (.get deterministic-engineering.init.exports Scenarios) resource-lifecycle scope))
      (def methods (.ref scene 'methods))
      (def original
        (path-expand "languages-engineering/rust/concurrency/resource-control/backpressure-memory" root))
      (call-with-temporary-directory
       "native-context"
       (lambda (crate)
         (create-directory (path-expand "src" crate))
         (for-each
          (lambda (name) (copy-file (path-expand name original) (path-expand name crate)))
          '("Cargo.toml" "Cargo.lock" "src/main.rs"))
         (def context
           ((.ref scene 'capture)
            root
            LifecycleProfile
            crate
            (getenv "RESOURCE_CARGO")
            (getenv "RESOURCE_RUSTC")
            'context-test))
         ;; A capture must use its actual owner's nominal contract.
         (validate (.get scene domain context-contract) context)
         (check-equal? (eq? ((.ref methods 'context-current!) context) context) #t)
         ;; Result admission runs after a real Context has passed owner membership.
         (def review-calls 0)
         (def wrong-result-scope
           (validate
            (.get scene contracts scope)
            (.cc
                (resource-lifecycle-scope
                 (.get scene domain)
                 (.get scene evidence)
                 (.get scene contracts scope))
              'open-review
              (lambda (_context)
                (set! review-calls (1+ review-calls))
                'not-a-session))))
         (check-exception ((.get wrong-result-scope open-review) context) TypeError?)
         (check-equal? review-calls 1)
         (def session ((.ref scene 'open-review) context))
         (check-equal? (object? session) #t)
         (def frozen (gerbil-ascent-session-run session))
         (def obligations ((.get frozen rows-of) 'obligation))
         (check-equal? (pair? obligations) #t)
         (check-equal? ((.get frozen rows-of) 'support) '())
         (check-exception
          ((.ref scene 'open-review) (.cc context 'profile LargerPayloadProfile))
          (lambda (_) #t))
         (check-exception
          ((.ref scene 'open-review)
           (.cc context 'profile
                (.cc LifecycleProfile 'factors (cons 'cache (.ref LifecycleProfile 'factors)))) )
          (lambda (_) #t))
         (check-exception
          ((.ref scene 'open-review)
           (.cc context 'scopes
                (cons (car (.ref context 'scopes)) (cdr (cdr (.ref context 'scopes))))))
          (lambda (_) #t))
         (def source (path-expand "src/main.rs" crate))
         (def text (call-with-input-file source read-all-as-string))
         (call-with-output-file
             (list path: source truncate: #t)
           (lambda (p) (display text p) (display "\n// Changed bytes, unchanged intended protocol.\n" p)))
         (check-exception ((.ref scene 'open-review) context) stale-source-context?)
         (def revised
           ((.ref scene 'capture)
            root
            LifecycleProfile
            crate
            (getenv "RESOURCE_CARGO")
            (getenv "RESOURCE_RUSTC")
            'context-test))
         (check-equal? (equal? (.ref revised 'snapshot) (.ref context 'snapshot)) #f)
         (check-equal? (equal? (scope-basis context 'source) (scope-basis revised 'source)) #f)
         (for-each
          (lambda (kind)
            (check-equal? (scope-basis context kind) (scope-basis revised kind)))
          '(model arithmetic cache runtime workload inventory))
         (def refreshed-session ((.ref scene 'open-review) revised))
         (check-equal? (object? refreshed-session) #t)
         (def refreshed (gerbil-ascent-session-run refreshed-session))
         (check-equal? ((.get frozen rows-of) 'obligation) obligations)
         (check-equal? ((.get frozen rows-of) 'support) '())
         (check-equal? ((.get refreshed rows-of) 'support) '())
         ;; Capture currentness is not a method attestation or execution permission.
         (check-equal? ((.get refreshed rows-of) 't_use) '()))))))
