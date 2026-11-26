// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.zero-trust.data-lineage-disclosure
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel k-anonymity-narrowing step=stepSinglingOut max-steps=6 itf="size(h.possibleIds) < 2"
// @countermodel disclosure-budget step=stepBudgetOverrun max-steps=6 itf="h.disclosures > 2"
// Limits: Finite cardinality-based singling-out indicator (k=2 over 4 records); does not provide differential privacy or inference resistance against auxiliary side-information.
module data_lineage_disclosure {
  import authority_currentness.* from "../authority-currentness/AuthorityCurrentness"
  type State = { possibleIds: Set[int], disclosures: int }
  var h: State
  action init = h' = { possibleIds: Set(1, 2, 3, 4), disclosures: 0 }
  action discloseSet(cand: Set[int]): bool = if ((h.disclosures < 2 and size(h.possibleIds.intersect(cand)) >= 2)) h' = h.with("possibleIds", h.possibleIds.intersect(cand)).with("disclosures", (h.disclosures + 1)) else h' = h
  action disclose = { nondet cand = Set(Set(1, 2, 3), Set(2, 3, 4), Set(1, 2), Set(2, 4)).oneOf()
    discloseSet(cand) }
  action step = any { disclose }
  val safety = (size(h.possibleIds) >= 2 and h.disclosures <= 2)
  // Countermodel threat.zero-trust.data-lineage-disclosure.singling-out (dropped guard: k-anonymity-narrowing)
  action discloseUnchecked(cand: Set[int]): bool = if ((h.disclosures < 2 and true)) h' = h.with("possibleIds", h.possibleIds.intersect(cand)).with("disclosures", (h.disclosures + 1)) else h' = h
  action stepSinglingOut = any { step, { nondet cand = Set(Set(1, 2, 3), Set(2, 3, 4), Set(1, 2), Set(2, 4)).oneOf()
    discloseUnchecked(cand) } }
  // Countermodel threat.zero-trust.data-lineage-disclosure.budget-overrun (dropped guard: disclosure-budget)
  action discloseOverBudget(cand: Set[int]): bool = if ((true and size(h.possibleIds.intersect(cand)) >= 2)) h' = h.with("possibleIds", h.possibleIds.intersect(cand)).with("disclosures", (h.disclosures + 1)) else h' = h
  action stepBudgetOverrun = any { step, { nondet cand = Set(Set(1, 2, 3), Set(2, 3, 4), Set(1, 2), Set(2, 4)).oneOf()
    discloseOverBudget(cand) } }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run validNarrowingAboveFloorTest = init.then(discloseSet(Set(1, 2, 3))).then(discloseSet(Set(2, 3, 4))).then(all { assert(size(h.possibleIds) == 2), assert(safety), h' = h })
  run singlingOutQueryRejectedTest = init.then(discloseSet(Set(1, 2))).then(discloseSet(Set(2, 4))).then(all { assert(size(h.possibleIds) == 2), assert(h.disclosures == 1), assert(safety), h' = h })
  run singlingOutCountermodelTest = init.then(discloseSet(Set(1, 2))).then(discloseUnchecked(Set(2, 4))).then(checkUnsafe)
}
