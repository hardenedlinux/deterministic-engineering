;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-only

;;; -*- Gerbil -*-
(import
  :clan/poo/object
  (only-in :clan/poo/mop validate)
  :gerbil-ascent/rules/interface
  (only-in :gerbil-ascent/rules/declaration rule-module-program)
  "../../profiles/gateway.ss"
  "./objects.ss"
  "./config.ss")
(export
  gateway-review-scope
  gateway-scope-rows)

;; This finite fixture mapping is not a cryptographic identity implementation.
;; Every semantic parameter used here is explicit. Host source/lockfile capture
;; and verified method receipts remain external obligations.
(def (scope-key fields)
  (call-with-output-string (lambda (port) (write fields port))))

(def (gateway-scope-rows profile usage source)
  (list
   (list usage 'inventory (.ref profile 'inventory))
   (list usage 'source source)
   (list
    usage
    'runtime
    (scope-key
     (list
      (.ref profile 'runtime)
      (.ref profile 'lock)
      (.ref profile 'tokio-workers)
      (.ref profile 'rayon-workers)
      (.ref profile 'cpu-budget))))
   (list
    usage
    'workload
    (scope-key
     (list
      (.ref profile 'workload)
      (.ref profile 'capacity)
      (.ref profile 'queue)
      (.ref profile 'cache-bytes))))
   (list
    usage
    'model
    (scope-key
     (list
      'owners-v1
      (.ref profile 'capacity)
      (.ref profile 'queue)
      (.ref profile 'factors))))
   (list
    usage
    'arithmetic
    (scope-key
     (list
      'sum-v1
      (.ref profile 'capacity)
      (.ref profile 'queue)
      (.ref profile 'item)
      (.ref profile 'fixed)
      (.ref profile 'cache-bytes)
      (.ref profile 'budget))))
   (list usage 'cache (scope-key (list 'cache-v1 (.ref profile 'cache-bytes))))))

(.def GatewayReviewScenario.
  domain: (error "Gateway example requires its domain")
  evidence: (error "Gateway example requires its evidence Module")
  entry: (.get domain entry)
  Scenario: (.cc GatewayCase 'profile (.get Config profile))
  ;; These profiles remain independently authored fixture publications.
  cases: (list LocalProfile Cap2Profile CacheProfile RetryProfile)
  scope-rows: gateway-scope-rows
  methods: (.get domain methods)
  open-review: (lambda (profile usage snapshot source (captured-scopes #f))
                 (validate (.get domain profile-contract) profile)
                 (unless (eq? entry (.get domain entry)) (error "Scenario entry differs from selected domain"))
                 (unless (and (symbol? usage) (string? snapshot) (string? source))
                   (error "explicit usage, snapshot and source required"))
                 ((.get evidence open-review)
                  entry
                  profile
                  usage
                  snapshot
                  (or captured-scopes (scope-rows profile usage source)))))
(def (gateway-review-scope selected-domain selected-evidence)
  (.o (:: @ GatewayReviewScenario.)
      domain: selected-domain
      evidence: selected-evidence))
