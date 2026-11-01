;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; -*- Gerbil -*-
(import :std/test :deterministic-engineering/init :clan/poo/object
        :deterministic-engineering/profiles/gateway
        :gerbil-ascent/rules/interface)
(export gateway-initial-test gateway-method-test gateway-capacity-test gateway-cache-retry-test gateway-source-test gateway-boundaries-test gateway-counter-test)

(def scene (.get (.get deterministic-engineering.init.exports Scenarios) gateway-review scope))
(def entry (.ref scene 'entry))
(def expected-obligations
  '((u1 BP-O01 review) (u1 BP-O02 quint) (u1 BP-O03 lean) (u1 BP-O04 review)
    (u1 BP-O07 native) (u1 TR-O01 native) (u1 TR-O02 review) (u1 TR-O03 quint)))
(def c1-sum "(sum-v1 2 2 64 128 0 512)")
(def c1-model "(owners-v1 2 2 (bounded-retention tokio rayon))")
(def c1-runtime "(\"fixture/tokio+rayon-config-v1\" \"fixture/Cargo.lock-v1\" 2 2 4)")
(def sum-row '(wsum BP-O03 lean "V/lean-fixture" pass))
(def sum-check '(wsum "V/lean-fixture" "A/method-fixture"))
(def (open profile (usage 'u1) (snapshot "snap/C1") (source "rust/source-v1"))
  ((.ref scene 'open-review) profile usage snapshot source))
(def (rows result relation)
  (unless (.ref result 'finished) (error "unfinished inference"))
  ((.ref result 'rows-of) relation))
(def (same-set? a b)
  (and (= (length a) (length b)) (andmap (lambda (r) (and (member r b) #t)) a)))
(def (publish! s witnesses inputs checks)
  (gerbil-ascent-session-replace-sources! s
    (list (cons 'witness witnesses) (cons 'witness_input inputs) (cons 'checked checks))))
(def (change-cut! s profile usage snapshot source)
  (gerbil-ascent-session-replace-sources! s
    (list (cons 'application (list (list usage snapshot (.ref entry 'identity))))
          (cons 'factor (map (lambda (f) (list usage f)) (.ref profile 'factors)))
          (cons 'scope ((.ref scene 'scope-rows) profile usage source)))))

(def gateway-initial-test
  (test-suite "Gateway initial"
    (test-case "C1 derives eight literal obligations from Library and Tokio/Rayon factors"
      (def s (open LocalProfile))
      (def r (gerbil-ascent-session-run s))
      (check-equal? (same-set? (rows r 'obligation) expected-obligations) #t)
      (check-equal? (same-set? (rows r 'pending) expected-obligations) #t)
      (check-equal? (rows r 'support) '())
      (check-equal? (rows r 'uncovered_factor) '())
      (check-equal? (and (member '(u1 async-cpu-handoff) (rows r 'factor)) #t) #t))))

(def gateway-method-test
  (test-suite "Gateway method"
    (test-case "raw pass is pending; checked exact witness produces T-use and support"
      (def s (open LocalProfile))
      (publish! s (list sum-row) (list (list 'wsum 'arithmetic c1-sum)) '())
      (check-equal? (rows (gerbil-ascent-session-run s) 'support) '())
      (gerbil-ascent-session-replace-source! s 'checked (list sum-check))
      (def r (gerbil-ascent-session-run s))
      (check-equal? (rows r 'support) '((u1 BP-O03 wsum "V/lean-fixture" "A/method-fixture")))
      (check-equal? (rows r 't_use) '((u1 "snap/C1" BP-O03 wsum)))
      (check-equal? (length (rows r 'pending)) 7))))

(def gateway-capacity-test
  (test-suite "Gateway capacity"
    (test-case "C1 to C2 invalidates application without deleting late or historical evidence"
      (def s (open LocalProfile))
      (publish! s (list sum-row) (list (list 'wsum 'arithmetic c1-sum)) (list sum-check))
      (def frozen (gerbil-ascent-session-run s))
      (change-cut! s Cap2Profile 'u2 "snap/C2" "rust/source-v1")
      (def changed (gerbil-ascent-session-run s))
      (check-equal? (rows changed 'support) '())
      (check-equal? (rows changed 'mismatch)
        '((u2 BP-O03 wsum arithmetic "(sum-v1 4 2 64 128 0 512)" "(sum-v1 2 2 64 128 0 512)")))
      (check-equal? (rows changed 'witness) (list sum-row))
      ;; A late old-snapshot pass remains queryable but does not acquire u2 support.
      (gerbil-ascent-session-append-source! s 'witness '(late BP-O03 lean "V/late-C1" pass))
      (gerbil-ascent-session-append-source! s 'witness_input (list 'late 'arithmetic c1-sum))
      (gerbil-ascent-session-append-source! s 'checked '(late "V/late-C1" "A/late"))
      (def late (gerbil-ascent-session-run s))
      (check-equal? (rows late 'support) '())
      (check-equal? (length (rows late 'witness)) 2)
      (check-equal? (rows frozen 'support) '((u1 BP-O03 wsum "V/lean-fixture" "A/method-fixture")))
      (check-equal? (rows frozen 'application) '((u1 "snap/C1" rust.resources.backpressure-memory))))))

(def gateway-cache-retry-test
  (test-suite "Gateway cache-retry"
    (test-case "cache and retry introduce their own obligations; unknown factors stay discoverable"
      (def s (open CacheProfile))
      (publish! s (list sum-row) (list (list 'wsum 'arithmetic c1-sum)) (list sum-check))
      (def cache (gerbil-ascent-session-run s))
      (check-equal? (and (member '(u1 CA-O01 native) (rows cache 'obligation)) #t) #t)
      (check-equal? (length (rows cache 'obligation)) 9)
      (check-equal? (rows cache 'support) '())
      (check-equal? (rows cache 'mismatch)
        '((u1 BP-O03 wsum arithmetic "(sum-v1 2 2 64 128 128 512)" "(sum-v1 2 2 64 128 0 512)")))
      (change-cut! s RetryProfile 'retry "snap/retry" "rust/source-v1")
      (gerbil-ascent-session-append-source! s 'factor '(retry unmodeled-plugin))
      (def retry (gerbil-ascent-session-run s))
      (check-equal? (and (member '(retry BP-O05 quint) (rows retry 'obligation)) #t) #t)
      (check-equal? (rows retry 'uncovered_factor) '((retry unmodeled-plugin))))))

(def gateway-source-test
  (test-suite "Gateway source"
    (test-case "source change reuses conditional math/model while reopening correspondence"
      (def s (open LocalProfile))
      (publish! s
        (list sum-row '(wmodel BP-O02 quint "V/model-fixture" pass)
              '(wmap BP-O04 review "V/mapping-fixture" pass))
        (list (list 'wsum 'arithmetic c1-sum) (list 'wmodel 'model c1-model)
              (list 'wmap 'model c1-model) (list 'wmap 'source "rust/source-v1")
              (list 'wmap 'runtime c1-runtime))
        (list sum-check '(wmodel "V/model-fixture" "A/model") '(wmap "V/mapping-fixture" "A/map")))
      (check-equal? (length (rows (gerbil-ascent-session-run s) 'support)) 3)
      (change-cut! s LocalProfile 'new-source "snap/source2" "rust/source-v2")
      (def r (gerbil-ascent-session-run s))
      (check-equal? (same-set? (rows r 'support)
        '((new-source BP-O03 wsum "V/lean-fixture" "A/method-fixture")
          (new-source BP-O02 wmodel "V/model-fixture" "A/model"))) #t)
      (check-equal? (rows r 'mismatch)
        '((new-source BP-O04 wmap source "rust/source-v2" "rust/source-v1"))))))

(def gateway-boundaries-test
  (test-suite "Gateway boundaries"
    (test-case "incomplete and extra closures, wrong methods and invalid source types cannot support"
      (def s (open LocalProfile))
      (publish! s
        (list sum-row '(extra BP-O03 lean "V/extra" pass) '(wrong BP-O03 native "V/wrong" pass))
        (list (list 'extra 'arithmetic c1-sum) '(extra unknown "value"))
        (list sum-check '(extra "V/extra" "A/extra") '(wrong "V/wrong" "A/wrong")))
      (def r (gerbil-ascent-session-run s))
      (check-equal? (rows r 'support) '())
      (check-equal? (rows r 'missing_input) '((u1 BP-O03 wsum arithmetic)))
      (check-equal? (rows r 'extra_input) '((u1 BP-O03 extra unknown)))
      (check-exception (gerbil-ascent-session-replace-source! s 'scope '((u1 source 42))) (lambda (_) #t))
      (check-equal? (rows (gerbil-ascent-session-run s) 'scope) (rows r 'scope)))))

(def gateway-counter-test
  (test-suite "Gateway counter"
    (test-case "opposing validated evidence stays visible beside support"
      (def s (open LocalProfile))
      (publish! s (list sum-row '(wcounter BP-O03 lean "V/counter-fixture" fail))
        (list (list 'wsum 'arithmetic c1-sum) (list 'wcounter 'arithmetic c1-sum))
        (list sum-check '(wcounter "V/counter-fixture" "A/counter")))
      (def r (gerbil-ascent-session-run s))
      (check-equal? (length (rows r 'support)) 1)
      (check-equal? (rows r 'counter)
        '((u1 BP-O03 wcounter "V/counter-fixture" "A/counter"))))))

