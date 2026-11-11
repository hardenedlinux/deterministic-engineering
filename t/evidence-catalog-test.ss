;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;;; Catalog control inputs exercise the real native engine; no method receipt is fabricated.
(import
  :std/test
  :clan/poo/object
  :deterministic-engineering/init
  :gerbil-ascent/program/session
  (only-in :clan/poo/mop TypeError?))
(export evidence-catalog-test)

(def evidence (.get deterministic-engineering.init.exports Library evidence))
(def generic (.get deterministic-engineering.init.exports Library backpressure-memory entry))
(def rust (.get deterministic-engineering.init.exports Library rust-resources entry))
(def (rows result relation) ((.get result rows-of) relation))
(def (same-rows? actual expected)
  (and (= (length actual) (length expected))
       (andmap (lambda (row) (and (member row expected) #t)) actual)))

(def evidence-catalog-test
  (test-suite "Catalog-owned meaning in the shared Evidence engine"
    (test-case "Tokio and Rayon imply handoff only in the selected specialization"
      (def profile (.o factors: '(tokio rayon)))
      (def parent-session
        ((.get evidence open-review) generic profile 'parent "cut/parent" '()))
      (def child-session
        ((.get evidence open-review) rust profile 'child "cut/child" '()))
      (check-equal? (.get generic factor-implications) '())
      (check-equal? (rows (gerbil-ascent-session-run parent-session) 'obligation) '())
      (def frozen (gerbil-ascent-session-run child-session))
      (check-equal?
        (and (member '(child TR-O03 quint) (rows frozen 'obligation)) #t) #t)
      (gerbil-ascent-session-replace-source! child-session 'catalog_factor_rule '())
      (def changed (gerbil-ascent-session-run child-session))
      (check-equal? (member '(child TR-O03 quint) (rows changed 'obligation)) #f)
      (check-equal? (member '(child async-cpu-handoff) (rows changed 'factor)) #f)
      (check-equal?
        (and (member '(child TR-O03 quint) (rows frozen 'obligation)) #t) #t))

    (test-case "binary rules chain to a finite fixed point without crossing entry or usage"
      (def session
        ((.get evidence open-review) generic (.o factors: '()) 'unused "cut/unused" '()))
      (gerbil-ascent-session-replace-sources! session
        (list
          (cons 'application '((u1 "cut/1" first) (u2 "cut/2" second) (u3 "cut/3" first)))
          (cons 'catalog_rule '((first result DONE review) (second result OTHER review)))
          (cons 'catalog_dependency '((first DONE source) (second OTHER runtime)))
          (cons 'catalog_factor_rule
            '((first left right middle) (first middle right result) (first result right middle)))
          (cons 'factor '((u1 left) (u1 right) (u2 left) (u2 right) (u3 left)))))
      (def result (gerbil-ascent-session-run session))
      ;; Literal gold is independent of the interpreter and row ordering.
      (check-equal? (rows result 'obligation) '((u1 DONE review)))
      (check-equal? (rows result 'requires) '((u1 DONE source)))
      (check-equal?
        (same-rows? (rows result 'factor)
          '((u1 left) (u1 right) (u1 middle) (u1 result)
            (u2 left) (u2 right) (u3 left))) #t)
      (check-equal? (rows result 'support) '()))

    (test-case "same-named obligations retain each Catalog's dependency set"
      (def session
        ((.get evidence open-review) generic (.o factors: '()) 'unused "cut/unused" '()))
      (gerbil-ascent-session-replace-sources! session
        (list
          (cons 'application '((u1 "cut/1" first) (u2 "cut/2" second)))
          (cons 'catalog_rule '((first selected SAME review) (second selected SAME review)))
          (cons 'catalog_dependency '((first SAME source) (second SAME runtime)))
          (cons 'factor '((u1 selected) (u2 selected)))))
      (def result (gerbil-ascent-session-run session))
      (check-equal?
        (same-rows? (rows result 'requires) '((u1 SAME source) (u2 SAME runtime))) #t)
      (check-equal?
        (same-rows? (rows result 'pending) '((u1 SAME review) (u2 SAME review))) #t))

    (test-case "malformed factor rules refuse at the published native Type boundary"
      (for-each
        (lambda (invalid)
          (check-exception
            ((.get evidence open-review)
              (.cc rust 'factor-implications invalid)
              (.o factors: '(tokio rayon)) 'bad "cut/bad" '())
            TypeError?))
        '(((tokio rayon)) ((tokio rayon async-cpu-handoff extra))
          ((tokio "rayon" async-cpu-handoff)) ((tokio . rayon)))))))
