// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.execution.agent-tool-circuit-breaker
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel breaker-closed-at-commit step=stepExecWhileTripped max-steps=6 itf="h.execWhileTripped == true"
// @countermodel lease-epoch-current step=stepStaleLeaseAfterTrip max-steps=6 itf="h.staleLeaseCommit == true"
// @countermodel human-only-rearm step=stepAgentSelfRearm max-steps=6 itf="h.agentSelfRearmed == true"
// @countermodel tool-budget-bounded step=stepBudgetRunaway max-steps=6 itf="h.budgetOverrun == true"
// Limits: Finite single-lease execution breaker and armed-window budget abstraction; does not model OS process SIGKILL signal delivery latencies, hardware watchdogs, or distributed consensus across multi-region executors.
module agent_tool_circuit_breaker {
  import authority_currentness.* from "../../zero-trust/authority-currentness/AuthorityCurrentness"
  type State = { breakerTripped: bool, tripEpoch: int, budgetUsed: int, leaseActive: bool, leaseEpoch: int, execWhileTripped: bool, staleLeaseCommit: bool, agentSelfRearmed: bool, budgetOverrun: bool }
  var h: State
  action init = h' = { breakerTripped: false, tripEpoch: 1, budgetUsed: 0, leaseActive: false, leaseEpoch: 0, execWhileTripped: false, staleLeaseCommit: false, agentSelfRearmed: false, budgetOverrun: false }
  action acquireToolLease = if ((not(h.breakerTripped) and not(h.leaseActive))) h' = h.with("leaseActive", true).with("leaseEpoch", h.tripEpoch) else h' = h
  action commitToolEffect = if ((h.leaseActive and not(h.breakerTripped) and epochCurrent(h.tripEpoch, h.leaseEpoch) and h.budgetUsed < 1)) h' = h.with("leaseActive", false).with("leaseEpoch", 0).with("budgetUsed", (h.budgetUsed + 1)).with("execWhileTripped", (h.execWhileTripped or h.breakerTripped)).with("staleLeaseCommit", (h.staleLeaseCommit or h.tripEpoch != h.leaseEpoch)).with("budgetOverrun", (h.budgetOverrun or h.budgetUsed >= 1)) else h' = h
  action tripBreaker = if (not(h.breakerTripped)) h' = h.with("breakerTripped", true) else h' = h
  action rearmBreakerAs(isAgent: bool, verifiedHuman: bool): bool = if ((h.breakerTripped and h.tripEpoch < 4 and (not(isAgent) and verifiedHuman))) h' = h.with("breakerTripped", false).with("tripEpoch", (h.tripEpoch + 1)).with("budgetUsed", 0).with("agentSelfRearmed", (h.agentSelfRearmed or isAgent or not(verifiedHuman))) else h' = h
  action rearmBreaker = { nondet isAgent = Set(false, true).oneOf()
    nondet verifiedHuman = Set(false, true).oneOf()
    rearmBreakerAs(isAgent, verifiedHuman) }
  action cancelStaleLease = if ((h.leaseActive and (h.breakerTripped or h.leaseEpoch != h.tripEpoch))) h' = h.with("leaseActive", false).with("leaseEpoch", 0) else h' = h
  action step = any { acquireToolLease, commitToolEffect, tripBreaker, rearmBreaker, cancelStaleLease }
  val safety = (not(h.execWhileTripped) and not(h.staleLeaseCommit) and not(h.agentSelfRearmed) and not(h.budgetOverrun) and h.budgetUsed <= 1)
  // Countermodel threat.execution.agent-tool-circuit-breaker.exec-while-tripped (dropped guard: breaker-closed-at-commit)
  action commitToolWhileTripped = if ((h.leaseActive and true and epochCurrent(h.tripEpoch, h.leaseEpoch) and h.budgetUsed < 1)) h' = h.with("leaseActive", false).with("leaseEpoch", 0).with("budgetUsed", (h.budgetUsed + 1)).with("execWhileTripped", (h.execWhileTripped or h.breakerTripped)).with("staleLeaseCommit", (h.staleLeaseCommit or h.tripEpoch != h.leaseEpoch)).with("budgetOverrun", (h.budgetOverrun or h.budgetUsed >= 1)) else h' = h
  action stepExecWhileTripped = any { step, commitToolWhileTripped }
  // Countermodel threat.execution.agent-tool-circuit-breaker.stale-lease-after-trip (dropped guard: lease-epoch-current)
  action commitToolStaleLease = if ((h.leaseActive and not(h.breakerTripped) and true and h.budgetUsed < 1)) h' = h.with("leaseActive", false).with("leaseEpoch", 0).with("budgetUsed", (h.budgetUsed + 1)).with("execWhileTripped", (h.execWhileTripped or h.breakerTripped)).with("staleLeaseCommit", (h.staleLeaseCommit or h.tripEpoch != h.leaseEpoch)).with("budgetOverrun", (h.budgetOverrun or h.budgetUsed >= 1)) else h' = h
  action stepStaleLeaseAfterTrip = any { step, commitToolStaleLease }
  // Countermodel threat.execution.agent-tool-circuit-breaker.agent-self-rearm (dropped guard: human-only-rearm)
  action rearmBreakerUnchecked(isAgent: bool, verifiedHuman: bool): bool = if ((h.breakerTripped and h.tripEpoch < 4 and true)) h' = h.with("breakerTripped", false).with("tripEpoch", (h.tripEpoch + 1)).with("budgetUsed", 0).with("agentSelfRearmed", (h.agentSelfRearmed or isAgent or not(verifiedHuman))) else h' = h
  action stepAgentSelfRearm = any { step, { nondet isAgent = Set(false, true).oneOf()
    nondet verifiedHuman = Set(false, true).oneOf()
    rearmBreakerUnchecked(isAgent, verifiedHuman) } }
  // Countermodel threat.execution.agent-tool-circuit-breaker.budget-runaway (dropped guard: tool-budget-bounded)
  action commitToolNoBudgetCap = if ((h.leaseActive and not(h.breakerTripped) and epochCurrent(h.tripEpoch, h.leaseEpoch) and true)) h' = h.with("leaseActive", false).with("leaseEpoch", 0).with("budgetUsed", (h.budgetUsed + 1)).with("execWhileTripped", (h.execWhileTripped or h.breakerTripped)).with("staleLeaseCommit", (h.staleLeaseCommit or h.tripEpoch != h.leaseEpoch)).with("budgetOverrun", (h.budgetOverrun or h.budgetUsed >= 1)) else h' = h
  action stepBudgetRunaway = any { step, commitToolNoBudgetCap }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run validLeaseCommitTripAndRearmTest = init.then(acquireToolLease).then(commitToolEffect).then(tripBreaker).then(rearmBreakerAs(false, true)).then(acquireToolLease).then(commitToolEffect).then(all { assert(h.tripEpoch == 2), assert(h.budgetUsed == 1), assert(safety), h' = h })
  run tripBlocksInFlightLeaseAndAgentRearmTest = init.then(acquireToolLease).then(tripBreaker).then(commitToolEffect).then(rearmBreakerAs(true, false)).then(rearmBreakerAs(false, true)).then(commitToolEffect).then(all { assert(h.budgetUsed == 0), assert(not(h.execWhileTripped)), assert(not(h.staleLeaseCommit)), assert(not(h.agentSelfRearmed)), assert(safety), h' = h })
  run budgetCapBlocksRunawayToolTest = init.then(acquireToolLease).then(commitToolEffect).then(acquireToolLease).then(commitToolEffect).then(all { assert(h.budgetUsed == 1), assert(not(h.budgetOverrun)), assert(safety), h' = h })
  run execWhileTrippedCountermodelTest = init.then(acquireToolLease).then(tripBreaker).then(commitToolWhileTripped).then(checkUnsafe)
  run staleLeaseAfterTripCountermodelTest = init.then(acquireToolLease).then(tripBreaker).then(rearmBreakerAs(false, true)).then(commitToolStaleLease).then(checkUnsafe)
  run agentSelfRearmCountermodelTest = init.then(tripBreaker).then(rearmBreakerUnchecked(true, false)).then(checkUnsafe)
  run budgetRunawayCountermodelTest = init.then(acquireToolLease).then(commitToolEffect).then(acquireToolLease).then(commitToolNoBudgetCap).then(checkUnsafe)
}
