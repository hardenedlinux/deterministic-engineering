// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.effect-containment
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12 const="MaxSignatures=1"
// @countermodel not-revoked step=stepStaleRecovery max-steps=6 itf="h.signatures >= 1 and h.lastSignedPaused == true"
// @countermodel clear-verified step=stepFalseClear max-steps=6 itf="h.cleared == true and h.witness == false"
// Limits: Finite containment abstraction; verified/finalized/noCode bits abstract trusted Host observations, not EVM/consensus proofs.
module effect_containment {
  const MaxSignatures: int
  type State = { delegated: bool, paused: bool, revoked: bool, everPaused: bool, clearPending: bool, cleared: bool, witness: bool, burned: bool, signatures: int, lastSignedPaused: bool, lastSignedDelegated: bool }
  var h: State
  action init = h' = { delegated: false, paused: false, revoked: false, everPaused: false, clearPending: false, cleared: false, witness: false, burned: false, signatures: 0, lastSignedPaused: false, lastSignedDelegated: false }
  action delegate = if ((h.signatures == 0 and not(h.delegated))) h' = h.with("delegated", true) else h' = h
  action attempt(bound: bool): bool = if ((bound and not(h.delegated) and not(h.paused) and not(h.revoked) and not(h.clearPending) and not(h.burned) and h.signatures < MaxSignatures)) h' = h.with("burned", true).with("signatures", (h.signatures + 1)).with("lastSignedPaused", h.everPaused).with("lastSignedDelegated", h.delegated) else h' = h
  action sign = { nondet bound = Set(false, true).oneOf()
    attempt(bound) }
  action pause = h' = h.with("paused", true).with("revoked", true).with("everPaused", true)
  action recoverAs(liveRevoked: bool): bool = h' = h.with("paused", h.paused).with("revoked", (h.revoked or liveRevoked or h.paused))
  action recover = { nondet live = Set(false, true).oneOf()
    recoverAs(live) }
  action submitClear = if ((h.paused and h.revoked and h.delegated)) h' = h.with("clearPending", true) else h' = h
  action observeAs(verified: bool, finalized: bool, noCode: bool): bool = if ((h.clearPending and (verified and finalized and noCode))) h' = h.with("delegated", false).with("cleared", true).with("witness", (verified and finalized and noCode)) else h' = h
  action observe = { nondet verified = Set(false, true).oneOf()
    nondet finalized = Set(false, true).oneOf()
    nondet noCode = Set(false, true).oneOf()
    observeAs(verified, finalized, noCode) }
  action step = any { delegate, sign, pause, recover, submitClear, observe }
  val safety = (h.signatures <= MaxSignatures and (h.signatures == 0 or (not(h.lastSignedPaused) and not(h.lastSignedDelegated))) and (not(h.cleared) or h.witness))
  // Countermodel threat.effect-containment.stale-recovery (dropped guard: not-revoked)
  action staleRecoverAs(liveRevoked: bool): bool = h' = h.with("paused", false).with("revoked", false)
  action stepStaleRecovery = any { step, { nondet live = Set(false, true).oneOf()
    staleRecoverAs(live) } }
  // Countermodel threat.effect-containment.false-clear (dropped guard: clear-verified)
  action falseClearAs(verified: bool, finalized: bool, noCode: bool): bool = if ((h.clearPending and true)) h' = h.with("delegated", false).with("cleared", true).with("witness", (verified and finalized and noCode)) else h' = h
  action stepFalseClear = any { step, { nondet verified = Set(false, true).oneOf()
    nondet finalized = Set(false, true).oneOf()
    nondet noCode = Set(false, true).oneOf()
    falseClearAs(verified, finalized, noCode) } }
  run cleanSignTest = init.then(attempt(true)).then(all { assert(h.signatures == 1), assert(safety), h' = h })
  run pausedBlocksSignTest = init.then(pause).then(attempt(true)).then(all { assert(h.signatures == 0), assert(safety), h' = h })
  run signThenPauseRemainsSafeTest = init.then(attempt(true)).then(pause).then(all { assert(h.signatures == 1), assert(not(h.lastSignedPaused)), assert(safety), h' = h })
  run staleRecoveryCountermodelTest = init.then(pause).then(staleRecoverAs(false)).then(attempt(true)).then(all { assert(h.signatures == 1), assert(h.lastSignedPaused), assert(not(safety)), h' = h })
  run falseClearCountermodelTest = init.then(delegate).then(pause).then(submitClear).then(falseClearAs(false, false, false)).then(all { assert(h.cleared), assert(not(h.witness)), assert(not(safety)), h' = h })
}
