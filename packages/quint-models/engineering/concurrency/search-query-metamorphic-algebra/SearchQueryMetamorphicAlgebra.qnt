// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.search-query-metamorphic-algebra
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel strip-qualifier-from-text-match step=stepQualifierLeak max-steps=6 itf="h.qualifierLeaked == true"
// @countermodel replace-prior-scope-axis step=stepStaleScopeShadow max-steps=6 itf="h.effectiveScopeEpoch != h.activeScopeEpoch"
// @countermodel clip-tab-hit-test-to-viewport step=stepClippedTabHit max-steps=6 itf="h.phantomTabHit == true"
// Limits: Finite metamorphic algebra abstraction over 2-epoch scope replacement, axis qualifiers, negation monotonicity, and clipped viewport hit-tests; concrete UTF-8 case folding and arbitrary query fuzzing are tested via Go testing.F and Rust proptest.
module concurrency_search_query_metamorphic_algebra {
  type State = { hasQualifier: bool, hasNegation: bool, activeScopeEpoch: int, effectiveScopeEpoch: int, matchedCount: int, clippedClicksIgnored: int, qualifierLeaked: bool, phantomTabHit: bool }
  var h: State
  action init = h' = { hasQualifier: false, hasNegation: false, activeScopeEpoch: 0, effectiveScopeEpoch: 0, matchedCount: 2, clippedClicksIgnored: 0, qualifierLeaked: false, phantomTabHit: false }
  action applyQualifier = if (not(h.hasQualifier)) h' = h.with("hasQualifier", true).with("qualifierLeaked", false).with("matchedCount", if (false) 0 else h.matchedCount) else h' = h
  action applyScopeReplace = if (h.activeScopeEpoch < 2) h' = h.with("activeScopeEpoch", (h.activeScopeEpoch + 1)).with("effectiveScopeEpoch", if (true) (h.activeScopeEpoch + 1) else if (h.effectiveScopeEpoch > 0) h.effectiveScopeEpoch else (h.activeScopeEpoch + 1)) else h' = h
  action addNegationFilter = if ((not(h.hasNegation) and h.matchedCount > 0)) h' = h.with("hasNegation", true).with("matchedCount", (h.matchedCount - 1)) else h' = h
  action clickClippedTab = if (h.clippedClicksIgnored < 2) h' = h.with("clippedClicksIgnored", (h.clippedClicksIgnored + 1)).with("phantomTabHit", false) else h' = h
  action resetQuery = if ((h.hasQualifier or h.hasNegation or h.activeScopeEpoch > 0)) h' = h.with("hasQualifier", false).with("hasNegation", false).with("activeScopeEpoch", 0).with("effectiveScopeEpoch", 0).with("matchedCount", 2) else h' = h
  action step = any { applyQualifier, applyScopeReplace, addNegationFilter, clickClippedTab, resetQuery }
  val safety = (not(h.qualifierLeaked) and h.effectiveScopeEpoch == h.activeScopeEpoch and not(h.phantomTabHit) and h.matchedCount <= 2)
  // Countermodel engineering.concurrency.search-query-metamorphic-algebra.qualifier-leak (dropped guard: strip-qualifier-from-text-match)
  action applyQualifierLeaked = if (not(h.hasQualifier)) h' = h.with("hasQualifier", true).with("qualifierLeaked", true).with("matchedCount", if (true) 0 else h.matchedCount) else h' = h
  action stepQualifierLeak = any { step, applyQualifierLeaked }
  // Countermodel engineering.concurrency.search-query-metamorphic-algebra.stale-scope-shadow (dropped guard: replace-prior-scope-axis)
  action applyScopePrependShadowed = if (h.activeScopeEpoch < 2) h' = h.with("activeScopeEpoch", (h.activeScopeEpoch + 1)).with("effectiveScopeEpoch", if (false) (h.activeScopeEpoch + 1) else if (h.effectiveScopeEpoch > 0) h.effectiveScopeEpoch else (h.activeScopeEpoch + 1)) else h' = h
  action stepStaleScopeShadow = any { step, applyScopePrependShadowed }
  // Countermodel engineering.concurrency.search-query-metamorphic-algebra.clipped-tab-hit (dropped guard: clip-tab-hit-test-to-viewport)
  action clickClippedTabPhantom = if (h.clippedClicksIgnored < 2) h' = h.with("clippedClicksIgnored", (h.clippedClicksIgnored + 1)).with("phantomTabHit", true) else h' = h
  action stepClippedTabHit = any { step, clickClippedTabPhantom }
  action checkMetamorphicSafe = all { assert(not(h.qualifierLeaked)), assert(h.effectiveScopeEpoch == h.activeScopeEpoch), assert(not(h.phantomTabHit)), assert(h.clippedClicksIgnored > 0), assert(safety), h' = h }
  action checkMetamorphicViolation = all { assert((h.qualifierLeaked or not(h.effectiveScopeEpoch == h.activeScopeEpoch) or h.phantomTabHit)), assert(not(safety)), h' = h }
  run metamorphicLifecycleTest = init.then(applyQualifier).then(applyScopeReplace).then(applyScopeReplace).then(addNegationFilter).then(clickClippedTab).then(resetQuery).then(checkMetamorphicSafe)
  run qualifierLeakRefutedTest = init.then(applyQualifierLeaked).then(checkMetamorphicViolation)
  run staleScopeShadowRefutedTest = init.then(applyScopeReplace).then(applyScopePrependShadowed).then(checkMetamorphicViolation)
  run clippedTabPhantomRefutedTest = init.then(clickClippedTabPhantom).then(checkMetamorphicViolation)
}
