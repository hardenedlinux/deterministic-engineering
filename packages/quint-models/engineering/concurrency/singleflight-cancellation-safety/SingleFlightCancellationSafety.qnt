// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.singleflight-cancellation-safety
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel drop-guard-reset-inflight step=stepLeaderDropLockout max-steps=6 itf="h.inFlight and not(h.leaderActive)"
// @countermodel arm-notify-before-check step=stepUnarmedLostWakeup max-steps=6 itf="h.stuckWaiters > 0"
// Limits: Finite 2-waiter single-flight coordinator abstraction; verifies leader cancellation drop-guard cleanup and armed notify registration, not OS thread scheduler fairness.
module concurrency_singleflight_cancellation_safety {
  type State = { inFlight: bool, leaderActive: bool, armedWaiters: int, stuckWaiters: int, completedSyncs: int }
  var h: State
  action init = h' = { inFlight: false, leaderActive: false, armedWaiters: 0, stuckWaiters: 0, completedSyncs: 0 }
  action acquireLeader = if ((not(h.inFlight) and h.completedSyncs < 3)) h' = h.with("inFlight", true).with("leaderActive", true) else h' = h
  action coalesceWaiter = if ((h.inFlight and h.armedWaiters < 2)) h' = h.with("armedWaiters", (h.armedWaiters + 1)).with("stuckWaiters", 0) else h' = h
  action completeLeader = if (h.leaderActive) h' = h.with("inFlight", false).with("leaderActive", false).with("armedWaiters", 0).with("completedSyncs", (h.completedSyncs + 1)) else h' = h
  action cancelLeader = if (h.leaderActive) h' = h.with("leaderActive", false).with("inFlight", false).with("armedWaiters", if (false) h.armedWaiters else 0) else h' = h
  action step = any { acquireLeader, coalesceWaiter, completeLeader, cancelLeader }
  val safety = ((not(h.inFlight) or h.leaderActive) and h.stuckWaiters == 0 and (h.inFlight or h.armedWaiters == 0))
  // Countermodel engineering.concurrency.singleflight-cancellation-safety.leader-drop-lockout (dropped guard: drop-guard-reset-inflight)
  action cancelLeaderWithoutGuard = if (h.leaderActive) h' = h.with("leaderActive", false).with("inFlight", true).with("armedWaiters", if (true) h.armedWaiters else 0) else h' = h
  action stepLeaderDropLockout = any { step, cancelLeaderWithoutGuard }
  // Countermodel engineering.concurrency.singleflight-cancellation-safety.unarmed-lost-wakeup (dropped guard: arm-notify-before-check)
  action coalesceWaiterUnarmed = if ((h.inFlight and h.armedWaiters < 2)) h' = h.with("armedWaiters", (h.armedWaiters + 1)).with("stuckWaiters", (h.stuckWaiters + 1)) else h' = h
  action stepUnarmedLostWakeup = any { step, coalesceWaiterUnarmed }
  action checkSingleFlightSafe = all { assert(not(h.inFlight)), assert(h.armedWaiters == 0), assert(h.stuckWaiters == 0), assert(h.completedSyncs > 0), assert(safety), h' = h }
  action checkSingleFlightDeadlock = all { assert(((h.inFlight and not(h.leaderActive)) or h.stuckWaiters > 0)), assert(not(safety)), h' = h }
  run cancelAndRecoverTest = init.then(acquireLeader).then(coalesceWaiter).then(cancelLeader).then(acquireLeader).then(coalesceWaiter).then(completeLeader).then(checkSingleFlightSafe)
  run leaderDropLockoutRefutedTest = init.then(acquireLeader).then(coalesceWaiter).then(cancelLeaderWithoutGuard).then(checkSingleFlightDeadlock)
  run unarmedLostWakeupRefutedTest = init.then(acquireLeader).then(coalesceWaiterUnarmed).then(checkSingleFlightDeadlock)
}
