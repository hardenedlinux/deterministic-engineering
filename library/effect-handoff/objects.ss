;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Domain-owned guarded effect handoff model; weakened countermodel auto-derived via (guard ...).
;;; Emergent safety (zero synthetic unsafe flag).
(import :clan/poo/object
        (only-in "../authority-currentness/objects.ss" AuthorityCurrentnessModel))
(export EffectHandoffModel NoDurabilityCountermodel)

(.def (EffectHandoffModel @ AuthorityCurrentnessModel)
  identity: 'threat.effect-handoff
  family: 'threat.effect-handoff
  quint-module: "effect_handoff"
  quint-file: "EffectHandoff.qnt"
  domain-dir: "threat/effect-handoff"
  quint-imports: '(("authority_currentness" "../authority-currentness/AuthorityCurrentness"))
  rules: '((effect-handoff-once HAND-ONCE quint)
           (effect-handoff-no-durability HAND-NODUR quint))
  dependencies: '((HAND-ONCE source) (HAND-ONCE profile) (HAND-ONCE method)
                  (HAND-NODUR source) (HAND-NODUR profile) (HAND-NODUR method))
  invariant: "Prepared effects commit durably under current authority and emit at most MaxSends times while retaining unknown outcomes."
  parameters: '((MaxSends "int"))
  verify-const-bindings: '((MaxSends "1"))
  state: '((phase "int" "0")
           (epoch "int" "0")
           (planned "int" "0")
           (paused "bool" "false")
           (fresh "bool" "true")
           (credential "bool" "true")
           (bytes "bool" "true")
           (durable "bool" "false")
           (unknown "bool" "false")
           (sent "int" "0"))
  guards: '((authority-current (call isCurrent (. h paused) (. h fresh) (. h credential) (. h bytes)))
            (epoch-current (call epochCurrent (. h epoch) (. h planned)))
            (durable-ack (and (= (. h phase) 2) (. h durable))))
  transitions:
  '((current
     (val current (call isCurrent (. h paused) (. h fresh) (. h credential) (. h bytes))))
    (prepare
     (action prepare ()
       (if (and (= (. h phase) 0) (not (. h unknown)) current)
         (set-h (phase 1) (planned (. h epoch)))
         (keep-h))))
    (commitAs
     (action commitAs ((verified "bool")) "bool"
       (if (and (= (. h phase) 1) verified current (call epochCurrent (. h epoch) (. h planned)))
         (set-h (phase 2) (durable #t) (unknown #t))
         (keep-h))))
    (commit
     (action commit ()
       (nondet ((verified (set #f #t)))
         (call commitAs verified))))
    (emit
     (action emit ()
       (if (and (guard durable-ack (and (= (. h phase) 2) (. h durable)))
                (!= (. h phase) 0)
                (!= (. h phase) 3)
                current
                (call epochCurrent (. h epoch) (. h planned))
                (< (. h sent) MaxSends))
         (set-h (phase 3) (unknown #t) (sent (+ (. h sent) 1)))
         (keep-h))))
    (pause (action pause () (set-h (paused #t))))
    (expire (action expire () (set-h (fresh #f))))
    (changeWriter (action changeWriter () (set-h (epoch 1))))
    (substitute (action substitute () (set-h (bytes #f))))
    (revoke (action revoke () (set-h (credential #f))))
    (recover (action recover () (keep-h)))
    (step
     (action step ()
       (any prepare commit emit pause expire changeWriter substitute revoke recover))))
  safety:
  '(and (<= (. h sent) MaxSends)
        (or (= (. h sent) 0) (and (. h durable) (. h unknown))))
  traces:
  '((blocked (action blocked () (all (assert (= (. h sent) 0)) (assert safety) (keep-h))))
    (once (action once () (all (assert (= (. h sent) 1)) (assert (. h unknown)) (assert safety) (keep-h))))
    (unsafe (action unsafe () (all (assert (not safety)) (keep-h))))
    (exactHandoffTest (run exactHandoffTest (then init prepare (call commitAs #t) emit once)))
    (absentAckTest (run absentAckTest (then init prepare (call commitAs #f) emit blocked)))
    (expiredTest (run expiredTest (then init prepare (call commitAs #t) expire emit blocked)))
    (pausedTest (run pausedTest (then init prepare pause (call commitAs #t) emit blocked)))
    (writerChangedTest (run writerChangedTest (then init prepare (call commitAs #t) changeWriter emit blocked)))
    (substitutedBytesTest (run substitutedBytesTest (then init prepare (call commitAs #t) substitute emit blocked)))
    (revokedCredentialTest (run revokedCredentialTest (then init prepare (call commitAs #t) revoke emit blocked)))
    (lostReplyTest (run lostReplyTest (then init prepare (call commitAs #t) emit recover prepare emit once))))
  countermodels: (list NoDurabilityCountermodel)
  limits: "Finite protocol abstraction; trusted bits summarize native interpreters; no cryptography, real CAS, codec correctness or Lean refinement is claimed.")

;; Weakened descendant: removes the durable-ack guard; must produce an unsafe witness.
(.def (NoDurabilityCountermodel @ EffectHandoffModel)
  identity: 'threat.effect-handoff.no-durability
  dropped-guard: 'durable-ack
  step-action: "stepNoDurability"
  derive-from-transition: 'emit
  derive-action-name: 'noDurability
  expected-itf-predicate: "h.sent >= 1 and not(h.durable)")
