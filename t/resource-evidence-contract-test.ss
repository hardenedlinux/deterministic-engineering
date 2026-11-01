;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; -*- Gerbil -*-
(import
  :std/test
  (only-in :clan/poo/object .o .cc .get)
  (only-in :clan/poo/mop validate TypeError?)
  :deterministic-engineering/init
  (only-in :deterministic-engineering/profiles/gateway LocalProfile)
  (only-in :gerbil-ascent/program/session
           gerbil-ascent-session-run gerbil-ascent-session-replace-sources!)
  (only-in :gerbil-ascent/rules/declaration ascent-rule-module rule-module?)
  (only-in "../library/drivers/evidence/types.ss"
           ResourceEvidenceScopeContract ResourceOpenReviewSignature ResourceMakeEvidenceSignature))

(export
  resource-evidence-contract-test)

(def expected-methods
  '((BP-O01 review) (BP-O02 quint) (BP-O03 lean) (BP-O04 review)
    (BP-O07 native) (TR-O01 native) (TR-O02 review) (TR-O03 quint)))

(def (expected-obligations usage)
  (map (lambda (row) (cons usage row)) expected-methods))

(def (same-rows? actual expected)
  (and (= (length actual) (length expected))
       (andmap (lambda (row) (and (member row expected) #t)) actual)))

(def resource-evidence-contract-test
  (test-suite "Native Evidence Module method boundaries"
    (test-case "actual publication constructs a checked Program and runs native inference"
      (def scope (.get deterministic-engineering.init.exports Library evidence scope))
      (def entry (.get deterministic-engineering.init.exports Library rust-resources scope entry))
      ;; Exercise the published boundary too, rather than only a test-local wrapper.
      (check-exception
       ((.get scope open-review) entry LocalProfile "invalid-usage" "source/A" '())
       TypeError?)
      (def checked (validate ResourceEvidenceScopeContract scope))
      (check-equal? (rule-module? ((.get checked make-evidence))) #t)
      (def session ((.get checked open-review) entry LocalProfile 'typed-current "source/A" '()))
      (def result (gerbil-ascent-session-run session))
      (check-equal?
       (same-rows? ((.get result rows-of) 'obligation) (expected-obligations 'typed-current))
       #t)
      (check-equal?
       (same-rows? ((.get result rows-of) 'pending) (expected-obligations 'typed-current))
       #t)
      (check-equal? ((.get result rows-of) 'support) '())
      (check-equal? (.get checked policy result-kind) 'recorded-only)
      (check-equal?
       (eq? scope (.get deterministic-engineering.init.exports Library evidence scope))
       #t))

    (test-case "invalid arguments and arity are rejected before the real operation runs"
      (def scope (.get deterministic-engineering.init.exports Library evidence scope))
      (def entry (.get deterministic-engineering.init.exports Library rust-resources scope entry))
      (def calls 0)
      (def operation
        (validate ResourceOpenReviewSignature
                  (lambda args
                    (set! calls (1+ calls))
                    (apply (.get scope open-review) args))))
      (for-each
       (lambda (arguments)
         (check-exception (apply operation arguments) TypeError?))
       (list
        (list (.cc entry 'rules '((bad-row))) LocalProfile 'u "source/A" '())
        (list entry (.cc LocalProfile 'factors '(tokio "rayon")) 'u "source/A" '())
        (list entry LocalProfile "u" "source/A" '())
        (list entry LocalProfile 'u "" '())
        (list entry LocalProfile 'u "source/A" '((u source)))
        (list entry LocalProfile 'u "source/A" '((u source "digest" extra)))
        (list entry LocalProfile 'u "source/A" '((u source 7)))
        (list entry LocalProfile 'u "source/A" '() 'extra)))
      (check-equal? calls 0)
      (def session (operation entry LocalProfile 'typed-effect "source/A" '()))
      (check-equal? calls 1)
      (check-equal?
       (same-rows? ((.get (gerbil-ascent-session-run session) rows-of) 'obligation)
                   (expected-obligations 'typed-effect))
       #t))

    (test-case "a callable with the wrong result cannot satisfy a method signature"
      (def make-invalid (validate ResourceMakeEvidenceSignature (lambda () (ascent-rule-module (.o)))))
      (check-exception (make-invalid) TypeError?)
      (def scope (.get deterministic-engineering.init.exports Library evidence scope))
      (def entry (.get deterministic-engineering.init.exports Library rust-resources scope entry))
      (def open-invalid (validate ResourceOpenReviewSignature (lambda args 'not-a-session)))
      (check-exception (open-invalid entry LocalProfile 'u "source/A" '()) TypeError?))

    (test-case "policy changes and undeclared permission fields cannot grant authority"
      (def scope (.get deterministic-engineering.init.exports Library evidence scope))
      (check-exception
       (validate ResourceEvidenceScopeContract
                 (.cc scope 'policy (.cc (.get scope policy) 'result-kind 'authorized)))
       TypeError?)
      (check-exception
       (validate ResourceEvidenceScopeContract (.cc scope 'authorization #t))
       TypeError?)
      (check-exception
       (validate ResourceEvidenceScopeContract
                 (.cc scope 'policy (.cc (.get scope policy) 'outcomes '(pass))))
       TypeError?))

    (test-case "typed normalization preserves immutable old results across a real source update"
      (def scope (.get deterministic-engineering.init.exports Library evidence scope))
      (def entry (.get deterministic-engineering.init.exports Library rust-resources scope entry))
      (def session ((.get scope open-review) entry LocalProfile 'typed-before "source/A" '()))
      (def before (gerbil-ascent-session-run session))
      (gerbil-ascent-session-replace-sources!
       session
       (list
        (cons 'application (list (list 'typed-after "source/B" (.get entry identity))))
        (cons 'factor (map (lambda (factor) (list 'typed-after factor)) (.get LocalProfile factors)))))
      (def after (gerbil-ascent-session-run session))
      (check-equal?
       (same-rows? ((.get before rows-of) 'obligation) (expected-obligations 'typed-before)) #t)
      (check-equal?
       (same-rows? ((.get after rows-of) 'obligation) (expected-obligations 'typed-after)) #t)
      (check-equal? ((.get before rows-of) 'support) '())
      (check-equal? ((.get after rows-of) 'support) '()))))
