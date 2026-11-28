// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.partial-order-delivery
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel require-causal-order step=stepBlindOrder max-steps=6 itf="h.outOfOrderApplied > 0"
// @countermodel require-dedup-witness step=stepDuplicateApply max-steps=6 itf="h.seq1Applied > 1"
// Limits: Finite 2-event causal stream abstraction with bounded deferral/duplicate counters; does not model arbitrary vector-clock DAG merges, unbounded reorder buffers, or Byzantine sender equivocation.
module partial_order_delivery {
  type State = { expectedSeq: int, seq1Arrived: bool, seq2Arrived: bool, seq1Applied: int, seq2Applied: int, outOfOrderApplied: int, duplicatesAbsorbed: int, outOfOrderDeferred: int }
  var h: State
  action init = h' = { expectedSeq: 1, seq1Arrived: false, seq2Arrived: false, seq1Applied: 0, seq2Applied: 0, outOfOrderApplied: 0, duplicatesAbsorbed: 0, outOfOrderDeferred: 0 }
  action arriveSeq1 = if (not(h.seq1Arrived)) h' = h.with("seq1Arrived", true) else h' = h
  action arriveSeq2 = if (not(h.seq2Arrived)) h' = h.with("seq2Arrived", true) else h' = h
  action deferOutOfOrderSeq2 = if ((h.seq2Arrived and h.expectedSeq < 2 and h.outOfOrderDeferred < 2)) h' = h.with("outOfOrderDeferred", (h.outOfOrderDeferred + 1)) else h' = h
  action applySeq1 = if ((h.seq1Arrived and h.seq1Applied == 0)) h' = h.with("seq1Applied", (h.seq1Applied + 1)).with("expectedSeq", if (h.expectedSeq == 1) 2 else h.expectedSeq) else h' = h
  action absorbDuplicateSeq1 = if ((h.seq1Arrived and h.seq1Applied >= 1 and h.duplicatesAbsorbed < 2)) h' = h.with("duplicatesAbsorbed", (h.duplicatesAbsorbed + 1)) else h' = h
  action applySeq2 = if ((h.seq2Arrived and h.expectedSeq == 2 and h.seq2Applied == 0)) h' = h.with("seq2Applied", (h.seq2Applied + 1)).with("expectedSeq", 3).with("outOfOrderApplied", if (h.seq1Applied == 0) (h.outOfOrderApplied + 1) else h.outOfOrderApplied) else h' = h
  action absorbDuplicateSeq2 = if ((h.seq2Arrived and h.seq2Applied >= 1 and h.duplicatesAbsorbed < 2)) h' = h.with("duplicatesAbsorbed", (h.duplicatesAbsorbed + 1)) else h' = h
  action step = any { arriveSeq1, arriveSeq2, deferOutOfOrderSeq2, applySeq1, absorbDuplicateSeq1, applySeq2, absorbDuplicateSeq2 }
  val safety = (h.seq1Applied <= 1 and h.seq2Applied <= 1 and h.outOfOrderApplied == 0 and (h.seq2Applied == 0 or h.seq1Applied == 1))
  // Countermodel engineering.defense.partial-order-delivery.blind-order (dropped guard: require-causal-order)
  action applySeq2BlindOrder = if ((h.seq2Arrived and true and h.seq2Applied == 0)) h' = h.with("seq2Applied", (h.seq2Applied + 1)).with("expectedSeq", 3).with("outOfOrderApplied", if (h.seq1Applied == 0) (h.outOfOrderApplied + 1) else h.outOfOrderApplied) else h' = h
  action stepBlindOrder = any { step, applySeq2BlindOrder }
  // Countermodel engineering.defense.partial-order-delivery.duplicate-apply (dropped guard: require-dedup-witness)
  action applySeq1Duplicate = if ((h.seq1Arrived and true)) h' = h.with("seq1Applied", (h.seq1Applied + 1)).with("expectedSeq", if (h.expectedSeq == 1) 2 else h.expectedSeq) else h' = h
  action stepDuplicateApply = any { step, applySeq1Duplicate }
  run reorderedThenCausalApplySafeTest = init.then(arriveSeq2).then(deferOutOfOrderSeq2).then(arriveSeq1).then(applySeq1).then(applySeq2).then(absorbDuplicateSeq2).then(all { assert(safety), assert(h.seq1Applied == 1), assert(h.seq2Applied == 1), assert(h.outOfOrderDeferred == 1), assert(h.duplicatesAbsorbed == 1), h' = h })
  run duplicateSeq1AbsorbedSafeTest = init.then(arriveSeq1).then(applySeq1).then(absorbDuplicateSeq1).then(all { assert(safety), assert(h.seq1Applied == 1), assert(h.duplicatesAbsorbed == 1), h' = h })
  run blindOutOfOrderViolatesSafetyTest = init.then(arriveSeq2).then(applySeq2BlindOrder).then(all { assert(not(safety)), assert(h.outOfOrderApplied > 0), h' = h })
  run duplicateDoubleApplyViolatesSafetyTest = init.then(arriveSeq1).then(applySeq1).then(applySeq1Duplicate).then(all { assert(not(safety)), assert(h.seq1Applied > 1), h' = h })
}
