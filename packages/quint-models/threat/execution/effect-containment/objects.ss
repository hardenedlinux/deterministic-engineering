;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Domain-owned effect containment and verified clearance witness model.
;;; Co-located Yuanxu unit: single source of truth alongside EffectContainment.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export EffectContainmentModel
        StaleRecoveryCountermodel
        FalseClearCountermodel)

(.def (EffectContainmentModel @ AuthorityCurrentnessModel)
  identity: 'threat.execution.effect-containment
  family: 'threat.execution.effect-containment
  title: "Assume-Breach Effect Containment & Finalized Clearance Witness"
  subdomain: 'quint.threat.execution
  papers:
  '(("S. Rose, O. Borchert, S. Mitchell & S. Connelly (NIST SP 800-207, 2020)"
     "Zero Trust Architecture: assume-breach pause, blast-radius containment, and verified re-admission.")
    ("M. S. Miller (Johns Hopkins PhD Thesis 2006)"
     "Robust Composition: non-recoverable revocation until explicit verified clearance witness."))
  quint-module: "effect_containment"
  quint-file: "EffectContainment.qnt"
  domain-dir: "threat/execution/effect-containment"
  rules:
  '((effect-containment-safe CONT-SAFE quint)
    (effect-containment-stale-recovery CONT-STALE quint)
    (effect-containment-false-clear CONT-FALSE quint))
  dependencies:
  '((CONT-SAFE source)
    (CONT-SAFE profile)
    (CONT-SAFE method)
    (CONT-STALE source)
    (CONT-STALE profile)
    (CONT-STALE method)
    (CONT-FALSE source)
    (CONT-FALSE profile)
    (CONT-FALSE method))
  invariant: "No signature occurs while delegated, paused, revoked, or clear-pending; clearance requires verified finalized witness."
  parameters:
  '((MaxSignatures "int"))
  verify-const-bindings:
  '((MaxSignatures "1"))
  state:
  '((delegated "bool" "false")
    (paused "bool" "false")
    (revoked "bool" "false")
    (everPaused "bool" "false")
    (clearPending "bool" "false")
    (cleared "bool" "false")
    (witness "bool" "false")
    (burned "bool" "false")
    (signatures "int" "0")
    (lastSignedPaused "bool" "false")
    (lastSignedDelegated "bool" "false"))
  guards:
  '((not-delegated (not (. h delegated)))
    (not-paused (not (. h paused)))
    (not-revoked (not (. h revoked)))
    (clear-verified (and verified finalized noCode)))
  guard-classifications:
  '((not-delegated precondition "Base containment framing precondition enforced in attempt; revocation and clearance witnessed by countermodels")
    (not-paused precondition "Base pause framing precondition enforced in attempt; revocation and clearance witnessed by countermodels"))
  transitions:
  '((delegate
      (action delegate ()
        (if (and (= (. h signatures) 0) (not (. h delegated)))
          (set-h (delegated #t))
          (keep-h))))
    (attempt
      (action attempt ((bound "bool")) "bool"
        (if (and bound
                 (not (. h delegated))
                 (not (. h paused))
                 (not (. h revoked))
                 (not (. h clearPending))
                 (not (. h burned))
                 (< (. h signatures) MaxSignatures))
          (set-h (burned #t)
                 (signatures (+ (. h signatures) 1))
                 (lastSignedPaused (. h everPaused))
                 (lastSignedDelegated (. h delegated)))
          (keep-h))))
    (sign
      (action sign ()
        (nondet ((bound (set #f #t)))
          (call attempt bound))))
    (pause
      (action pause ()
        (set-h (paused #t)
               (revoked #t)
               (everPaused #t))))
    (recoverAs
      (action recoverAs ((liveRevoked "bool")) "bool"
        (set-h (paused (guard not-revoked (. h paused) #f))
               (revoked (guard not-revoked
                               (or (. h revoked) liveRevoked (. h paused))
                               #f)))))
    (recover
      (action recover ()
        (nondet ((live (set #f #t)))
          (call recoverAs live))))
    (submitClear
      (action submitClear ()
        (if (and (. h paused) (. h revoked) (. h delegated))
          (set-h (clearPending #t))
          (keep-h))))
    (observeAs
      (action observeAs ((verified "bool") (finalized "bool") (noCode "bool")) "bool"
        (if (and (. h clearPending)
                 (guard clear-verified (and verified finalized noCode)))
          (set-h (delegated #f)
                 (cleared #t)
                 (witness (and verified finalized noCode)))
          (keep-h))))
    (observe
      (action observe ()
        (nondet ((verified (set #f #t))
                 (finalized (set #f #t))
                 (noCode (set #f #t)))
          (call observeAs verified finalized noCode))))
    (step
      (action step ()
        (any delegate sign pause recover submitClear observe))))
  safety:
  '(and (<= (. h signatures) MaxSignatures)
        (or (= (. h signatures) 0)
            (and (not (. h lastSignedPaused))
                 (not (. h lastSignedDelegated))))
        (or (not (. h cleared)) (. h witness)))
  traces:
  '((cleanSignTest
      (run cleanSignTest
        (then init (call attempt #t)
              (all (assert (= (. h signatures) 1))
                   (assert safety)
                   (keep-h)))))
    (pausedBlocksSignTest
      (run pausedBlocksSignTest
        (then init pause (call attempt #t)
              (all (assert (= (. h signatures) 0))
                   (assert safety)
                   (keep-h)))))
    (signThenPauseRemainsSafeTest
      (run signThenPauseRemainsSafeTest
        (then init (call attempt #t) pause
              (all (assert (= (. h signatures) 1))
                   (assert (not (. h lastSignedPaused)))
                   (assert safety)
                   (keep-h)))))
    (staleRecoveryCountermodelTest
      (run staleRecoveryCountermodelTest
        (then init pause (call staleRecoverAs #f) (call attempt #t)
              (all (assert (= (. h signatures) 1))
                   (assert (. h lastSignedPaused))
                   (assert (not safety))
                   (keep-h)))))
    (falseClearCountermodelTest
      (run falseClearCountermodelTest
        (then init delegate pause submitClear (call falseClearAs #f #f #f)
              (all (assert (. h cleared))
                   (assert (not (. h witness)))
                   (assert (not safety))
                   (keep-h))))))
  countermodels:
  (list StaleRecoveryCountermodel
        FalseClearCountermodel)
  limits: "Finite containment abstraction; verified/finalized/noCode bits abstract trusted Host observations, not EVM/consensus proofs.")

(.def (StaleRecoveryCountermodel @ EffectContainmentModel)
  identity: 'threat.execution.effect-containment.stale-recovery
  dropped-guard: 'not-revoked
  step-action: "stepStaleRecovery"
  derive-from-transition: 'recoverAs
  derive-action-name: 'staleRecoverAs
  derive-step-call: '(nondet ((live (set #f #t)))
                       (call staleRecoverAs live))
  expected-itf-predicate: "h.signatures >= 1 and h.lastSignedPaused == true")

(.def (FalseClearCountermodel @ EffectContainmentModel)
  identity: 'threat.execution.effect-containment.false-clear
  dropped-guard: 'clear-verified
  step-action: "stepFalseClear"
  derive-from-transition: 'observeAs
  derive-action-name: 'falseClearAs
  derive-step-call: '(nondet ((verified (set #f #t))
                              (finalized (set #f #t))
                              (noCode (set #f #t)))
                       (call falseClearAs verified finalized noCode))
  expected-itf-predicate: "h.cleared == true and h.witness == false")
