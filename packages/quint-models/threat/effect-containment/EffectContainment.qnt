// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// Projected from Scheme POO module threat.effect-containment. Do not edit by hand.
// Limits: Finite containment abstraction; verified/finalized/noCode bits abstract trusted Host observations, not EVM/consensus proofs.
module effect_containment {
  const MaxSignatures: int
  type State = { delegated: bool, paused: bool, revoked: bool, everPaused: bool, clearPending: bool, cleared: bool, witness: bool, burned: bool, signatures: int, unsafe: bool }
  var h: State
  action init = h' = { delegated: false, paused: false, revoked: false, everPaused: false, clearPending: false, cleared: false, witness: false, burned: false, signatures: 0, unsafe: false }
  action attempt(bound: bool): bool = if (bound and not(h.delegated) and not(h.paused) and not(h.revoked) and not(h.clearPending) and not(h.burned) and h.signatures < MaxSignatures + 1)
    h' = h.with("burned", true).with("signatures", h.signatures + 1)
      .with("unsafe", h.unsafe or h.everPaused or h.delegated or h.signatures >= MaxSignatures)
    else h' = h
  action sign = { nondet bound = Set(false, true).oneOf()
    attempt(bound) }
  action pause = h' = h.with("paused", true).with("revoked", true).with("everPaused", true)
  action recoverAs(liveRevoked: bool): bool =
    h' = h.with("revoked", h.revoked or liveRevoked or h.paused)
  action recover = { nondet live = Set(false, true).oneOf()
    recoverAs(live) }
  action submitClear = if (h.paused and h.revoked and h.delegated)
    h' = h.with("clearPending", true) else h' = h
  action observeAs(verified: bool, finalized: bool, noCode: bool): bool =
    if (h.clearPending and verified and finalized and noCode)
      h' = h.with("delegated", false).with("cleared", true).with("witness", true)
    else h' = h
  action observe = { nondet verified = Set(false, true).oneOf()
    nondet finalized = Set(false, true).oneOf()
    nondet noCode = Set(false, true).oneOf()
    observeAs(verified, finalized, noCode) }
  action step = any { sign, pause, recover, submitClear, observe }
  val safety = not(h.unsafe) and h.signatures <= MaxSignatures and (not(h.cleared) or h.witness)
  // Countermodel threat.effect-containment.stale-recovery (dropped guard: not-revoked)
  action staleRecover = if (h.paused)
    h' = h.with("paused", false).with("revoked", false) else h' = h
  action stepStaleRecovery = any { step, staleRecover }
  // Countermodel threat.effect-containment.false-clear (dropped guard: clear-verified)
  action falseClear = if (h.clearPending)
    h' = h.with("delegated", false).with("cleared", true) else h' = h
  action stepFalseClear = any { step, falseClear }
  run cleanSignTest = init.then(attempt(true)).then(all { assert(h.signatures == 1), assert(safety), h' = h })
  run pausedBlocksSignTest = init.then(pause).then(attempt(true)).then(all { assert(h.signatures == 0), assert(safety), h' = h })
}
