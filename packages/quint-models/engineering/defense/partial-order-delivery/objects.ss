;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; F4 / P2 / M2: Partial-order, delayed, and duplicated delivery boundary (10.153 E4).
;;; Proves that out-of-order deliveries must be explicitly deferred (not silently dropped
;;; or blindly applied), and duplicate deliveries must be explicitly absorbed via dedup
;;; witness rather than double-applied.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export PartialOrderDeliveryModel)

(.def (PartialOrderDeliveryModel @ ThreatModel.)
  identity: 'engineering.defense.partial-order-delivery
  family: 'engineering.defense.partial-order-delivery
  title: "Partial-Order & Duplicate Event Delivery Boundary"
  subdomain: 'quint.engineering.defense
  papers:
  '(("Deterministic Engineering (10.153 E4 / F4)"
     "Causal sequence admission, explicit OutOfOrderDeferred, and explicit DuplicateAbsorbed boundaries under reordered/duplicated networks.")
    ("L. Lamport (CACM 1978)"
     "Time, Clocks, and the Ordering of Events in a Distributed System."))
  quint-module: "partial_order_delivery"
  quint-file: "PartialOrderDelivery.qnt"
  domain-dir: "engineering/defense/partial-order-delivery"
  rules:
  '((partial-order-safe DE-POD-SAFE quint)
    (partial-order-countermodel DE-POD-COUNTER quint))
  dependencies:
  '((DE-POD-SAFE source)
    (DE-POD-SAFE profile)
    (DE-POD-SAFE method)
    (DE-POD-COUNTER source)
    (DE-POD-COUNTER profile)
    (DE-POD-COUNTER method))
  invariant: "Every causal event is applied at most once (seq1Applied <= 1 and seq2Applied <= 1), seq2 is never applied out of order before seq1 (outOfOrderApplied == 0), and duplicates/early arrivals are explicitly absorbed or deferred."
  limits: "Finite 2-event causal stream abstraction with bounded deferral/duplicate counters; does not model arbitrary vector-clock DAG merges, unbounded reorder buffers, or Byzantine sender equivocation.")
