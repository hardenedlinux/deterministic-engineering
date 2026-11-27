;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :std/test
        (only-in :tao3k/yuanxu/testing yuanxu-test-case)
        :clan/poo/object
        (only-in :clan/poo/type validate)
        :deterministic-engineering/library/search-engine/types
        :deterministic-engineering/library/search-engine/config
        :deterministic-engineering/library/search-engine/func
        :deterministic-engineering/library/search-engine/interface)
(export search-engine-contract-test)

(def search-engine-contract-test
  (test-suite "search-engine domain contract, Quality-Diversity (MAP-Elites / MMR) & tier routing"

    (yuanxu-test-case "Config validates sealed CatalogConfigContract and exposes search.neuro-symbolic-engine"
      (validate (.get CatalogConfigContract value-contract) Config)
      (validate (.get CatalogScopeContract value-contract) (.get SearchEngine core exports))
      (check-equal? (.get Config entry identity) 'search.neuro-symbolic-engine)
      (check-equal? (.get Config entry family) 'search.neuro-symbolic-engine))

    (yuanxu-test-case "select-niche-diverse-rows prevents mode collapse and maximizes niche coverage"
      (def raw-rows
        '(("new" "a.rs" 10) ("new" "b.rs" 20) ("new" "c.rs" 30) ("new" "d.rs" 40)
          ("parse" "a.rs" 50) ("parse" "b.rs" 60)
          ("solve" "c.rs" 70)))
      (def collapsed-report (compute-diversity-coverage-report (list (car raw-rows) (cadr raw-rows) (caddr raw-rows))))
      (def diverse (select-niche-diverse-rows raw-rows 3))
      (def diverse-report (compute-diversity-coverage-report diverse))
      (check-equal? (.get collapsed-report mode-collapsed?) #t)
      (check-equal? (.get collapsed-report unique-niches) 1)
      (check-equal? (map car diverse) '("new" "parse" "solve"))
      (check-equal? (.get diverse-report mode-collapsed?) #f)
      (check-equal? (.get diverse-report unique-niches) 3))

    (yuanxu-test-case "select-mmr-diverse-items balances relevance against redundancy"
      ;; Three items: a1 (niche A, rel 0.95), a2 (niche A, rel 0.92), b1 (niche B, rel 0.85)
      ;; Same niche similarity = 1.0, different niche similarity = 0.0.
      ;; Under lambda = 0.5, after picking a1, b1 scores 0.5*0.85 - 0.5*0 = 0.425 > a2 (0.5*0.92 - 0.5*1.0 = -0.04).
      (def candidates '((a1 a 0.95) (a2 a 0.92) (b1 b 0.85)))
      (def picked
        (select-mmr-diverse-items
          candidates 2 0.5
          (lambda (x) (caddr x))
          (lambda (x y) (if (eq? (cadr x) (cadr y)) 1.0 0.0))))
      (check-equal? (map car picked) '(a1 b1)))

    (yuanxu-test-case "classify-search-tier-intent routes intents to narrowest sound tier"
      (check-equal? (classify-search-tier-intent 'regex-search) 'l0-fast-ram)
      (check-equal? (classify-search-tier-intent 'impact-analysis) 'l1-relational-ascent)
      (check-equal? (classify-search-tier-intent 'collision-detection) 'l1-relational-ascent)
      (check-equal? (classify-search-tier-intent 'placement-solving) 'l2-dusa-choice)
      (check-equal? (classify-search-tier-intent 'disambiguation) 'l2-dusa-choice))

    (yuanxu-test-case "compute-hybrid-impact-coverage and decompose-zero-hit-stems guard coverage & 0-hit recovery"
      (def cov (compute-hybrid-impact-coverage 11 4 11))
      (check-equal? (.get cov ast-coverage-pct) 36)
      (check-equal? (.get cov hybrid-coverage-pct) 100)
      (check-equal? (.get cov requires-lexical-fallback?) #t)
      (check-equal? (.get cov complete-coverage?) #t)
      (def stems (decompose-zero-hit-stems "blocked-continuation|ContinuationBlocked|ToolUseConsistency"))
      (check-equal? (and (member "blocked" stems)
                         (member "continuation" stems)
                         (member "tool" stems)
                         (member "consistency" stems)
                         #t)
                    #t))))
