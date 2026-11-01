;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-only

(import :std/test :clan/poo/object
        (only-in :clan/poo/mop validate)
        "../library/concurrency/resource-control/backpressure-memory/abstract/objects.ss"
        "../library/drivers/rust-resources/objects.ss"
        "../library/concurrency/resource-control/backpressure-memory/tokio-rayon/objects.ss"
        "../library/drivers/rust-resources/types.ss"
        "../profiles/resource-lifecycle.ss")
(export library-model-chain-test)
(def selected-method-references
  (map (lambda (key) (method-ref (.ref RustMethodDefinitions key))) '(native quint lean)))
(def selected-integration-reference
  (method-ref (.get RustMethodDefinitions integration)))
(def (checked-rust)
  (validate (.get RustResourceModelContract value-contract)
    (specialize-backpressure BackpressureModel selected-method-references)))
(def library-model-chain-test
  (test-suite "Declared model lineage and independent review policies"
    (test-case "Generic to Rust to Integration retains exact immediate parents"
      (def rust (checked-rust))
      (def integrated
        (validate (.get BackpressureIntegrationContract value-contract)
          (make-backpressure-integration rust selected-integration-reference)))
      (check-equal? (eq? (.get rust parent) BackpressureModel) #t)
      (check-equal? (eq? (.get integrated parent) rust) #t)
      (check-equal? (.slot? rust 'generic-entry) #f)
      (check-equal? (.get integrated contract declaration-contract contract-version) "V1")
      (check-equal? (.get rust state-map)
                    '((waiting waiting)
                      (queued queued)
                      (cpu-running active)
                      (result-pending returned)
                      (cleanup cleanup)
                      (released released)))
      (check-equal? (length (.get integrated case-links)) 6))
    (test-case "wrong role or lost parent duty refuses at its expected Contract"
      (def rust (checked-rust))
      (check-exception (validate (.get RustResourceModelContract value-contract)
                                 (.cc rust 'parent #f)) error?)
      (check-exception (validate (.get RustResourceModelContract value-contract)
                                 (.cc rust 'state-map (cdr (.get rust state-map)))) error?)
      (check-exception (validate (.get RustResourceModelContract value-contract)
                                 (.cc rust 'state-map (cons '(waiting unknown) (cdr (.get rust state-map))))) error?)
      (check-exception (validate (.get RustResourceModelContract value-contract)
                                 (.cc rust 'rules (filter (lambda (r) (not (eq? (cadr r) 'BP-O02))) (.get rust rules)))) error?)
      (def integrated (make-backpressure-integration rust selected-integration-reference))
      (check-exception (validate (.get BackpressureIntegrationContract value-contract)
                                 (.cc integrated 'parent BackpressureModel)) error?)
      (check-exception (validate (.get BackpressureIntegrationContract value-contract)
                                 (.cc integrated 'state-map '())) error?)
      (check-exception (validate (.get BackpressureIntegrationContract value-contract)
                                 (.cc integrated 'parent (.cc rust 'parent #f))) error?))
    (test-case "coding and design policies are distinct roots with separate required duties"
      (def coding (validate (.get BackpressureReviewPolicyContract value-contract) BackpressureCodingPolicy))
      (def design (validate (.get BackpressureDesignReviewPolicyContract value-contract) BackpressureDesignPolicy))
      (check-equal? (.get coding parent) #f)
      (check-equal? (.get design parent) #f)
      (check-equal? (eq? coding design) #f)
      (check-equal? (.get design required-products) '(D01 D02 D03 D04 D05 D06 D07 D08 D09 D10))
      (check-exception (validate (.get BackpressureReviewPolicyContract value-contract) design) error?)
      (check-exception (validate (.get BackpressureDesignReviewPolicyContract value-contract)
                                 (.cc design 'grant #t)) error?)
      (check-exception (validate (.get BackpressureReviewPolicyContract value-contract)
                                 (.cc design 'contract BackpressureReviewPolicyContract)) error?)
      (check-exception (validate (.get BackpressureDesignReviewPolicyContract value-contract)
                                 (.cc design 'required-products '(D01))) error?)
      (check-exception (validate (.get BackpressureDesignReviewPolicyContract value-contract)
                                 (.cc design 'criteria '())) error?)
      (check-exception (validate (.get BackpressureReviewPolicyContract value-contract)
                                 (.cc coding 'model-ids '(unrelated-model))) error?))
    (test-case "Profile and structural context refuse undeclared fields and modes without acquiring files"
      (def selected-profile (validate ResourceNativeProfileContract LifecycleProfile))
      (check-equal? (.get selected-profile factors) (.get LifecycleProfile factors))
      (check-exception (validate ResourceNativeProfileContract (.cc selected-profile 'extra #t)) error?)
      (check-exception (validate ResourceProfileContract (.cc selected-profile 'capacity 3)) error?)
      (def context (.o root: "/fixture" entry: (checked-rust) profile: selected-profile
                       crate: "/fixture/crate" cargo: "/fixture/cargo" rustc: "/fixture/rustc"
                       mode: 'normal usage: 'fixture snapshot: "structural-test-only-not-issued-C"
                       scopes: (map (lambda (key) (list 'fixture key "test-only-not-acquired"))
                                    '(model arithmetic cache source runtime workload inventory))))
      (validate ResourceNativeContextContract context)
      (check-exception (validate ResourceNativeContextContract (.cc context 'mode 'unknown)) error?)
      (check-exception (validate ResourceNativeContextContract (.cc context 'origin #t)) error?)
      (check-exception (validate ResourceNativeContextContract
                                 (.cc context 'scopes (cdr (.get context scopes)))) error?))))


(export library-factor-inheritance-test)
(def library-factor-inheritance-test
  (test-suite "POO factor-rule inheritance"
    (test-case "specialization preserves a parent's declared factor rules and rejects loss"
      (def parent (.o (:: @ BackpressureModel)
                      factor-implications: => (cut append <> '((owned cleanup bounded-retention)))))
      (def held (.get parent factor-implications))
      (def child (specialize-backpressure parent selected-method-references))
      (validate (.get RustResourceModelContract value-contract) child)
      (check-equal? (.get parent factor-implications) held)
      (check-equal? (.get child factor-implications)
                    '((owned cleanup bounded-retention) (tokio rayon async-cpu-handoff)))
      (check-exception
       (validate (.get RustResourceModelContract value-contract)
                 (.cc child 'factor-implications '((tokio rayon async-cpu-handoff)))) error?))))
