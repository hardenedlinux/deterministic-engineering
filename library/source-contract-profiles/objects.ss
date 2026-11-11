;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Profiles consume strategies from the selected native owner, not a second import.
(import :clan/poo/object)
(export source-contract-profiles)

(def (source-contract-profiles selected-strategies)
  (def capacity-base
    (.o
      identity: 'c-capacity-body
      language: (.get selected-strategies c11)
      executor: (.get selected-strategies cbmc)
      obligation: 'CAP-BODY
      factor: 'checked-capacity
      method: (.get executor method)
      function: "capacity_harness"
      enforce: ""
      instrumentation: (.get selected-strategies direct)
      units: '("languages-engineering/c/numeric/bounded-capacity/capacity.c"
               "languages-engineering/c/numeric/bounded-capacity/parser.c"
               "languages-engineering/c/numeric/bounded-capacity/pool.c"
               "languages-engineering/c/numeric/bounded-capacity/proof.c")
      inputs: (cons "languages-engineering/c/numeric/bounded-capacity/capacity.h" units)
      expected-properties: '("capacity.result" "capacity.output-and-failure-frame")))
  (def lifetime-base
    (.o
      identity: 'cpp-lifetime
      language: (.get selected-strategies cpp11)
      executor: (.get selected-strategies cbmc)
      obligation: 'LIFE-BODY
      factor: 'resource-transfer
      method: (.get executor method)
      function: "lifetime_harness"
      enforce: ""
      instrumentation: (.get selected-strategies direct)
      units: '("languages-engineering/cpp/memory/resource-lifetime/proof.cpp")
      inputs: (cons "languages-engineering/cpp/memory/resource-lifetime/slot.hpp" units)
      expected-properties: '("owner.acquired" "owner.unique-after-transfer"
                             "owner.occupied-refusal" "owner.idempotent-release"
                             "owner.inner-destruction" "owner.outer-destruction"
                             "owner.occupied-preserves-both" "owner.self-refusal"
                             "owner.distinct-counter-destruction" "owner.empty-transfer")))
  (.o
    capacity-body: capacity-base
    capacity-contract:
    (.o (:: @ capacity-base)
      identity: 'c-capacity-contract
      function: "contract_harness"
      enforce: "capacity_total"
      instrumentation: (.get selected-strategies enforce)
      expected-properties:
      '("Check ensures clause of contract contract::capacity_total for function capacity_total"))
    capacity-callers:
    (.o (:: @ capacity-base)
      identity: 'c-capacity-callers
      obligation: 'CAP-CALLER
      factor: 'capacity-client
      function: "callers_harness"
      enforce: "capacity_total"
      instrumentation: (.get selected-strategies replace)
      expected-properties: '("parser.admission" "pool.admission"))
    capacity-native:
    (.o (:: @ capacity-base)
      identity: 'c-capacity-native
      obligation: 'CAP-NATIVE
      factor: 'native-capacity
      executor: (.get selected-strategies native)
      units: '("languages-engineering/c/numeric/bounded-capacity/capacity.c"
               "languages-engineering/c/numeric/bounded-capacity/parser.c"
               "languages-engineering/c/numeric/bounded-capacity/pool.c"
               "languages-engineering/c/numeric/bounded-capacity/native-test.c")
      expected-properties: '())
    lifetime-body: lifetime-base
    lifetime-native:
    (.o (:: @ lifetime-base)
      identity: 'cpp-lifetime-native
      obligation: 'LIFE-NATIVE
      factor: 'native-lifetime
      executor: (.get selected-strategies native)
      units: '("languages-engineering/cpp/memory/resource-lifetime/native-test.cpp")
      expected-properties: '())))
