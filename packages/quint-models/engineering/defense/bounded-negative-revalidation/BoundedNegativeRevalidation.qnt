// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.bounded-negative-revalidation
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel invalidate-dependent-review step=stepStaleNegReuse max-steps=6 itf="h.negDomainExpanded == true and h.oldNegReviewActive == true"
// @countermodel preserve-frozen-history step=stepGlobalHistoryPurge max-steps=6 itf="h.frozenCutIntact == false"
// @countermodel preserve-independent-method step=stepPurgeIndependentMethod max-steps=6 itf="h.independentMethodValid == false"
// @countermodel require-admitted-replacement step=stepRepeatFalseReason max-steps=6 itf="h.negDomainExpanded == true and h.currentReviewClosed == true and h.admittedReplacementReason == false"
// Limits: Finite single-counter expansion model of DE01 negative-dependency invalidation; does not model arbitrary multi-domain policy hierarchies or external artifact byte hashing.
module bounded_negative_revalidation {
  type State = { frozenCutIntact: bool, independentMethodValid: bool, negDomainExpanded: bool, oldNegReviewActive: bool, admittedReplacementReason: bool, currentReviewClosed: bool, newCounterReviewed: bool }
  var h: State
  action init = h' = { frozenCutIntact: true, independentMethodValid: true, negDomainExpanded: false, oldNegReviewActive: true, admittedReplacementReason: false, currentReviewClosed: true, newCounterReviewed: false }
  action arriveRelevantCounter = if (not(h.negDomainExpanded)) h' = h.with("negDomainExpanded", true).with("oldNegReviewActive", false).with("currentReviewClosed", false).with("frozenCutIntact", h.frozenCutIntact).with("independentMethodValid", h.independentMethodValid) else h' = h
  action supplyReplacementReason = if ((h.negDomainExpanded and not(h.admittedReplacementReason))) h' = h.with("admittedReplacementReason", true) else h' = h
  action recloseOldItemReview = if ((h.negDomainExpanded and not(h.currentReviewClosed) and h.admittedReplacementReason)) h' = h.with("currentReviewClosed", true) else h' = h
  action reviewNewCounter = if ((h.negDomainExpanded and not(h.newCounterReviewed))) h' = h.with("newCounterReviewed", true) else h' = h
  action step = any { arriveRelevantCounter, supplyReplacementReason, recloseOldItemReview, reviewNewCounter }
  val safety = (h.frozenCutIntact and h.independentMethodValid and (not(h.negDomainExpanded) or not(h.oldNegReviewActive)) and (not(h.negDomainExpanded) or not(h.currentReviewClosed) or h.admittedReplacementReason))
  // Countermodel engineering.defense.bounded-negative-revalidation.stale-neg-reuse (dropped guard: invalidate-dependent-review)
  action arriveCounterKeepStaleReview = if (not(h.negDomainExpanded)) h' = h.with("negDomainExpanded", true).with("oldNegReviewActive", h.oldNegReviewActive).with("currentReviewClosed", h.currentReviewClosed).with("frozenCutIntact", h.frozenCutIntact).with("independentMethodValid", h.independentMethodValid) else h' = h
  action stepStaleNegReuse = any { step, arriveCounterKeepStaleReview }
  // Countermodel engineering.defense.bounded-negative-revalidation.global-history-purge (dropped guard: preserve-frozen-history)
  action arriveCounterPurgeHistory = if (not(h.negDomainExpanded)) h' = h.with("negDomainExpanded", true).with("oldNegReviewActive", false).with("currentReviewClosed", false).with("frozenCutIntact", false).with("independentMethodValid", h.independentMethodValid) else h' = h
  action stepGlobalHistoryPurge = any { step, arriveCounterPurgeHistory }
  // Countermodel engineering.defense.bounded-negative-revalidation.purge-independent-method (dropped guard: preserve-independent-method)
  action arriveCounterPurgeMethod = if (not(h.negDomainExpanded)) h' = h.with("negDomainExpanded", true).with("oldNegReviewActive", false).with("currentReviewClosed", false).with("frozenCutIntact", h.frozenCutIntact).with("independentMethodValid", false) else h' = h
  action stepPurgeIndependentMethod = any { step, arriveCounterPurgeMethod }
  // Countermodel engineering.defense.bounded-negative-revalidation.repeat-false-reason (dropped guard: require-admitted-replacement)
  action recloseWithoutReplacement = if ((h.negDomainExpanded and not(h.currentReviewClosed) and true)) h' = h.with("currentReviewClosed", true) else h' = h
  action stepRepeatFalseReason = any { step, recloseWithoutReplacement }
  run boundedRevalidationTest = init.then(arriveRelevantCounter).then(all { assert(safety), assert(h.frozenCutIntact), assert(h.independentMethodValid), assert(not(h.oldNegReviewActive)), assert(not(h.currentReviewClosed)), h' = h }).then(supplyReplacementReason).then(recloseOldItemReview).then(reviewNewCounter).then(all { assert(safety), assert(h.currentReviewClosed), assert(h.newCounterReviewed), h' = h })
  run staleNegReuseCountermodelTest = init.then(arriveCounterKeepStaleReview).then(all { assert(not(safety)), assert(h.negDomainExpanded), assert(h.oldNegReviewActive), h' = h })
  run globalHistoryPurgeCountermodelTest = init.then(arriveCounterPurgeHistory).then(all { assert(not(safety)), assert(not(h.frozenCutIntact)), h' = h })
  run purgeMethodCountermodelTest = init.then(arriveCounterPurgeMethod).then(all { assert(not(safety)), assert(not(h.independentMethodValid)), h' = h })
  run repeatFalseReasonCountermodelTest = init.then(arriveRelevantCounter).then(recloseWithoutReplacement).then(all { assert(not(safety)), assert(h.currentReviewClosed), assert(not(h.admittedReplacementReason)), h' = h })
}
