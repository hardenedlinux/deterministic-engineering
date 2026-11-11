;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;;; -*- Gerbil -*-
(import :std/test :std/encoding/json
 "../library/backpressure-review/func.ss"
 "../library/backpressure-review/cross-intake.ss")
(export aitia-projection-test)
(def aitia-projection-test
 (test-suite "Pure Aitia projections preserve content and history identity"
  (test-case "JSON content comparison does not erase nested or missing information"
   (def left (hash ("records" (list (hash ("id" "counter-1") ("outcome" "fail"))))))
   (def right (hash ("records" (list (hash ("outcome" "fail") ("id" "counter-1"))))))
   (check-equal? (review-json-equal? left right) #t)
   (check-equal? (review-json-equal? left (hash ("records" '()))) #f)
   (check-equal? (review-json-equal? left (hash ("records" (list (hash ("id" "counter-1")))))) #f)
   (check-equal? (hash-ref (car (hash-ref left "records")) "outcome") "fail"))
  (test-case "owner lineage wire preserves signer policy supersession and target"
   (def body (hash ("signer" "reviewer") ("policy" "review") ("decision" "rejected")
     ("supersedes" '()) ("target" "target-1")))
   (def rows (list (list "record-1" body 'source)))
   (def wire (review-history-wire "owner-1" "technical-1" 'lineage rows))
   (check-equal? (call-with-input-string wire read)
     '(aitia-review-owner/v1 "owner-1" "technical-1" lineage
       (("record-1" ("reviewer" "review" "rejected" () "target-1") source))))
   (check-equal? (equal? wire (review-history-wire "owner-2" "technical-1" 'lineage rows)) #f))))
