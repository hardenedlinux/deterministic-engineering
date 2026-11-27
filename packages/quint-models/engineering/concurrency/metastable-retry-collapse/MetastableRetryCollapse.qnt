// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.metastable-retry-collapse
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel overload-admission-shed step=stepNoLoadShed max-steps=6 itf="h.queueDepth > 2"
// @countermodel retry-budget-cap step=stepUnboundedRetryStorm max-steps=6 itf="h.retriesPending > 1 or h.queueDepth > 2"
// Limits: Finite single-stage queue and retry-budget abstraction (queue cap=2, retry budget=1); models overload amplification and recovery bounds, not continuous service-time distributions or multi-hop network propagation delays.
module concurrency_metastable_retry {
  type State = { congested: bool, triggerCleared: bool, queueDepth: int, retriesPending: int, shedCount: int }
  var h: State
  action init = h' = { congested: false, triggerCleared: false, queueDepth: 0, retriesPending: 0, shedCount: 0 }
  action admitFresh = if ((h.queueDepth < 3 and h.shedCount < 3 and (not(h.congested) and h.queueDepth < 2))) h' = h.with("queueDepth", (h.queueDepth + 1)) else if ((h.queueDepth < 3 and h.shedCount < 3)) h' = h.with("shedCount", (h.shedCount + 1)) else h' = h
  action triggerCongestion = if (not(h.congested)) h' = h.with("congested", true).with("triggerCleared", false) else h' = h
  action timeoutAndRetry = if ((h.congested and h.queueDepth > 0 and h.queueDepth < 4 and h.shedCount < 3 and (h.retriesPending < 1 and h.queueDepth < 2))) h' = h.with("queueDepth", (h.queueDepth + 1)).with("retriesPending", (h.retriesPending + 1)) else if ((h.congested and h.queueDepth > 0 and h.shedCount < 3)) h' = h.with("shedCount", (h.shedCount + 1)) else h' = h
  action clearTrigger = if ((h.congested and not(h.triggerCleared))) h' = h.with("triggerCleared", true) else h' = h
  action drainNormal = if ((h.queueDepth > 0 and (not(h.congested) or h.triggerCleared))) h' = h.with("queueDepth", (h.queueDepth - 1)).with("retriesPending", if (h.retriesPending > 0) (h.retriesPending - 1) else 0).with("congested", if (h.queueDepth == 1) false else h.congested) else h' = h
  action step = any { admitFresh, triggerCongestion, timeoutAndRetry, clearTrigger, drainNormal }
  val safety = (h.queueDepth <= 2 and h.retriesPending <= 1 and h.retriesPending <= h.queueDepth)
  // Countermodel engineering.concurrency.metastable-retry-collapse.no-load-shed (dropped guard: overload-admission-shed)
  action admitFreshUnchecked = if ((h.queueDepth < 3 and h.shedCount < 3 and true)) h' = h.with("queueDepth", (h.queueDepth + 1)) else if ((h.queueDepth < 3 and h.shedCount < 3)) h' = h.with("shedCount", (h.shedCount + 1)) else h' = h
  action stepNoLoadShed = any { step, admitFreshUnchecked }
  // Countermodel engineering.concurrency.metastable-retry-collapse.unbounded-retry-storm (dropped guard: retry-budget-cap)
  action timeoutAndRetryUnchecked = if ((h.congested and h.queueDepth > 0 and h.queueDepth < 4 and h.shedCount < 3 and true)) h' = h.with("queueDepth", (h.queueDepth + 1)).with("retriesPending", (h.retriesPending + 1)) else if ((h.congested and h.queueDepth > 0 and h.shedCount < 3)) h' = h.with("shedCount", (h.shedCount + 1)) else h' = h
  action stepUnboundedRetryStorm = any { step, timeoutAndRetryUnchecked }
  action checkRecovered = all { assert(not(h.congested)), assert(h.queueDepth == 0), assert(h.retriesPending == 0), assert(safety), h' = h }
  action checkOverloadCollapse = all { assert((h.queueDepth > 2 or h.retriesPending > 1)), assert(not(safety)), h' = h }
  run boundedOverloadRecoveryTest = init.then(admitFresh).then(triggerCongestion).then(timeoutAndRetry).then(admitFresh).then(clearTrigger).then(drainNormal).then(drainNormal).then(checkRecovered)
  run noLoadShedRefutedTest = init.then(admitFresh).then(admitFresh).then(admitFreshUnchecked).then(checkOverloadCollapse)
  run unboundedRetryStormRefutedTest = init.then(admitFresh).then(triggerCongestion).then(timeoutAndRetryUnchecked).then(timeoutAndRetryUnchecked).then(checkOverloadCollapse)
}
