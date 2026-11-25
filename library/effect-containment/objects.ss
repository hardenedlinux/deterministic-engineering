;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Domain-owned effect containment and clearance witness model.
(import :clan/poo/object
        (only-in "../authority-currentness/objects.ss" AuthorityCurrentnessModel))
(export EffectContainmentModel StaleRecoveryCountermodel FalseClearCountermodel)

(.def (EffectContainmentModel @ AuthorityCurrentnessModel)
  identity: 'threat.effect-containment
  family: 'threat.effect-containment
  quint-module: "effect_containment"
  quint-file: "EffectContainment.qnt"
  domain-dir: "threat/effect-containment"
  rules: '((effect-containment-safe CONT-SAFE quint)
           (effect-containment-stale-recovery CONT-STALE quint)
           (effect-containment-false-clear CONT-FALSE quint))
  dependencies: '((CONT-SAFE source) (CONT-SAFE profile) (CONT-SAFE method)
                  (CONT-STALE source) (CONT-STALE profile) (CONT-STALE method)
                  (CONT-FALSE source) (CONT-FALSE profile) (CONT-FALSE method))
  invariant: "No signature occurs while delegated, paused, revoked, or clear-pending; clearance requires verified finalized witness."
  parameters: '((MaxSignatures "int"))
  state: '((delegated "bool" "false")
           (paused "bool" "false")
           (revoked "bool" "false")
           (everPaused "bool" "false")
           (clearPending "bool" "false")
           (cleared "bool" "false")
           (witness "bool" "false")
           (burned "bool" "false")
           (signatures "int" "0")
           (unsafe "bool" "false"))
  guards: '((not-delegated "not(h.delegated)")
            (not-paused "not(h.paused)")
            (not-revoked "not(h.revoked)")
            (clear-verified "verified and finalized and noCode"))
  transitions:
  '((attempt "action attempt(bound: bool): bool = if (bound and not(h.delegated) and not(h.paused) and not(h.revoked) and not(h.clearPending) and not(h.burned) and h.signatures < MaxSignatures + 1)\n    h' = h.with(\"burned\", true).with(\"signatures\", h.signatures + 1)\n      .with(\"unsafe\", h.unsafe or h.everPaused or h.delegated or h.signatures >= MaxSignatures)\n    else h' = h")
    (sign "action sign = { nondet bound = Set(false, true).oneOf()\n    attempt(bound) }")
    (pause "action pause = h' = h.with(\"paused\", true).with(\"revoked\", true).with(\"everPaused\", true)")
    (recoverAs "action recoverAs(liveRevoked: bool): bool =\n    h' = h.with(\"revoked\", h.revoked or liveRevoked or h.paused)")
    (recover "action recover = { nondet live = Set(false, true).oneOf()\n    recoverAs(live) }")
    (submitClear "action submitClear = if (h.paused and h.revoked and h.delegated)\n    h' = h.with(\"clearPending\", true) else h' = h")
    (observeAs "action observeAs(verified: bool, finalized: bool, noCode: bool): bool =\n    if (h.clearPending and verified and finalized and noCode)\n      h' = h.with(\"delegated\", false).with(\"cleared\", true).with(\"witness\", true)\n    else h' = h")
    (observe "action observe = { nondet verified = Set(false, true).oneOf()\n    nondet finalized = Set(false, true).oneOf()\n    nondet noCode = Set(false, true).oneOf()\n    observeAs(verified, finalized, noCode) }")
    (step "action step = any { sign, pause, recover, submitClear, observe }"))
  safety: "not(h.unsafe) and h.signatures <= MaxSignatures and (not(h.cleared) or h.witness)"
  traces:
  '((cleanSignTest "run cleanSignTest = init.then(attempt(true)).then(all { assert(h.signatures == 1), assert(safety), h' = h })")
    (pausedBlocksSignTest "run pausedBlocksSignTest = init.then(pause).then(attempt(true)).then(all { assert(h.signatures == 0), assert(safety), h' = h })"))
  countermodels: (list StaleRecoveryCountermodel FalseClearCountermodel)
  limits: "Finite containment abstraction; verified/finalized/noCode bits abstract trusted Host observations, not EVM/consensus proofs.")

(.def (StaleRecoveryCountermodel @ EffectContainmentModel)
  identity: 'threat.effect-containment.stale-recovery
  dropped-guard: 'not-revoked
  step-action: "stepStaleRecovery"
  counter-action: "action staleRecover = if (h.paused)\n    h' = h.with(\"paused\", false).with(\"revoked\", false) else h' = h\n  action stepStaleRecovery = any { step, staleRecover }"
  expected-itf-predicate: "h.unsafe == true")

(.def (FalseClearCountermodel @ EffectContainmentModel)
  identity: 'threat.effect-containment.false-clear
  dropped-guard: 'clear-verified
  step-action: "stepFalseClear"
  counter-action: "action falseClear = if (h.clearPending)\n    h' = h.with(\"delegated\", false).with(\"cleared\", true) else h' = h\n  action stepFalseClear = any { step, falseClear }"
  expected-itf-predicate: "h.cleared == true and h.witness == false")
