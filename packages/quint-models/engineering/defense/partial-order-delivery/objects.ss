;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; F4 / P2 / M2: Partial-order, delayed, and duplicated delivery boundary (10.153 E4).
;;; Proves that out-of-order deliveries must be explicitly deferred (not silently dropped
;;; or blindly applied), and duplicate deliveries must be explicitly absorbed via dedup
;;; witness rather than double-applied.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export PartialOrderDeliveryModel
        BlindOutOfOrderApplyCountermodel
        DuplicateDoubleApplyCountermodel)

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
  verify-depth: 10
  countermodel-depth: 6
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
  parameters: '()
  state:
  '((expectedSeq "int" "1")
    (seq1Arrived "bool" "false")
    (seq2Arrived "bool" "false")
    (seq1Applied "int" "0")
    (seq2Applied "int" "0")
    (outOfOrderApplied "int" "0")
    (duplicatesAbsorbed "int" "0")
    (outOfOrderDeferred "int" "0"))
  guards:
  '((require-causal-order (= (. h expectedSeq) 2))
    (require-dedup-witness (= (. h seq1Applied) 0)))
  transitions:
  '((arriveSeq1
      (action arriveSeq1 ()
        (if (not (. h seq1Arrived))
          (set-h (seq1Arrived #t))
          (keep-h))))
    (arriveSeq2
      (action arriveSeq2 ()
        (if (not (. h seq2Arrived))
          (set-h (seq2Arrived #t))
          (keep-h))))
    (deferOutOfOrderSeq2
      (action deferOutOfOrderSeq2 ()
        (if (and (. h seq2Arrived) (< (. h expectedSeq) 2) (< (. h outOfOrderDeferred) 2))
          (set-h (outOfOrderDeferred (+ (. h outOfOrderDeferred) 1)))
          (keep-h))))
    (applySeq1
      (action applySeq1 ()
        (if (and (. h seq1Arrived)
                 (guard require-dedup-witness (= (. h seq1Applied) 0)))
          (set-h (seq1Applied (+ (. h seq1Applied) 1))
                 (expectedSeq (if (= (. h expectedSeq) 1) 2 (. h expectedSeq))))
          (keep-h))))
    (absorbDuplicateSeq1
      (action absorbDuplicateSeq1 ()
        (if (and (. h seq1Arrived) (>= (. h seq1Applied) 1) (< (. h duplicatesAbsorbed) 2))
          (set-h (duplicatesAbsorbed (+ (. h duplicatesAbsorbed) 1)))
          (keep-h))))
    (applySeq2
      (action applySeq2 ()
        (if (and (. h seq2Arrived)
                 (guard require-causal-order (= (. h expectedSeq) 2))
                 (guard require-dedup-witness (= (. h seq2Applied) 0)))
          (set-h (seq2Applied (+ (. h seq2Applied) 1))
                 (expectedSeq 3)
                 (outOfOrderApplied
                   (if (= (. h seq1Applied) 0)
                     (+ (. h outOfOrderApplied) 1)
                     (. h outOfOrderApplied))))
          (keep-h))))
    (absorbDuplicateSeq2
      (action absorbDuplicateSeq2 ()
        (if (and (. h seq2Arrived) (>= (. h seq2Applied) 1) (< (. h duplicatesAbsorbed) 2))
          (set-h (duplicatesAbsorbed (+ (. h duplicatesAbsorbed) 1)))
          (keep-h))))
    (step
      (action step ()
        (any arriveSeq1 arriveSeq2 deferOutOfOrderSeq2
             applySeq1 absorbDuplicateSeq1 applySeq2 absorbDuplicateSeq2))))
  safety:
  '(and (<= (. h seq1Applied) 1)
        (<= (. h seq2Applied) 1)
        (= (. h outOfOrderApplied) 0)
        (or (= (. h seq2Applied) 0) (= (. h seq1Applied) 1)))
  traces:
  '((reorderedThenCausalApplySafeTest
      (run reorderedThenCausalApplySafeTest
        (then init arriveSeq2 deferOutOfOrderSeq2 arriveSeq1 applySeq1 applySeq2 absorbDuplicateSeq2
              (all (assert safety)
                   (assert (= (. h seq1Applied) 1))
                   (assert (= (. h seq2Applied) 1))
                   (assert (= (. h outOfOrderDeferred) 1))
                   (assert (= (. h duplicatesAbsorbed) 1))
                   (keep-h)))))
    (duplicateSeq1AbsorbedSafeTest
      (run duplicateSeq1AbsorbedSafeTest
        (then init arriveSeq1 applySeq1 absorbDuplicateSeq1
              (all (assert safety)
                   (assert (= (. h seq1Applied) 1))
                   (assert (= (. h duplicatesAbsorbed) 1))
                   (keep-h)))))
    (blindOutOfOrderViolatesSafetyTest
      (run blindOutOfOrderViolatesSafetyTest
        (then init arriveSeq2 applySeq2BlindOrder
              (all (assert (not safety))
                   (assert (> (. h outOfOrderApplied) 0))
                   (keep-h)))))
    (duplicateDoubleApplyViolatesSafetyTest
      (run duplicateDoubleApplyViolatesSafetyTest
        (then init arriveSeq1 applySeq1 applySeq1Duplicate
              (all (assert (not safety))
                   (assert (> (. h seq1Applied) 1))
                   (keep-h))))))
  countermodels:
  (list BlindOutOfOrderApplyCountermodel
        DuplicateDoubleApplyCountermodel)
  limits: "Finite 2-event causal stream abstraction with bounded deferral/duplicate counters; does not model arbitrary vector-clock DAG merges, unbounded reorder buffers, or Byzantine sender equivocation.")

(.def (BlindOutOfOrderApplyCountermodel @ PartialOrderDeliveryModel)
  identity: 'engineering.defense.partial-order-delivery.blind-order
  dropped-guard: 'require-causal-order
  step-action: "stepBlindOrder"
  derive-from-transition: 'applySeq2
  derive-action-name: 'applySeq2BlindOrder
  expected-itf-predicate: "h.outOfOrderApplied > 0")

(.def (DuplicateDoubleApplyCountermodel @ PartialOrderDeliveryModel)
  identity: 'engineering.defense.partial-order-delivery.duplicate-apply
  dropped-guard: 'require-dedup-witness
  step-action: "stepDuplicateApply"
  derive-from-transition: 'applySeq1
  derive-action-name: 'applySeq1Duplicate
  expected-itf-predicate: "h.seq1Applied > 1")
