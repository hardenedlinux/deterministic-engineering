;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; OAuth PAR + Crash-Safe Revocation Recovery threat model (RFC 9126 / RFC 7009).
;;; Emergent crash-recovery safety (zero synthetic unsafe flag); countermodels auto-derived via (guard ...).
(import :clan/poo/object
        (only-in "../authority-currentness/objects.ss" AuthorityCurrentnessModel))
(export OAuthRevocationRecoveryModel
        CrashDropsRevocationCountermodel
        UnboundParExchangeCountermodel)

(.def (OAuthRevocationRecoveryModel @ AuthorityCurrentnessModel)
  identity: 'threat.oauth-revocation-recovery
  family: 'threat.oauth-revocation-recovery
  quint-module: "oauth_revocation_recovery"
  quint-file: "OAuthRevocationRecovery.qnt"
  domain-dir: "threat/oauth-revocation-recovery"
  quint-imports: '(("authority_currentness" "../authority-currentness/AuthorityCurrentness"))
  rules: '((par-request-binding OAUTH-PAR-BIND quint)
           (durable-revoke-intent OAUTH-REV-DURABLE quint))
  dependencies: '((OAUTH-PAR-BIND source) (OAUTH-PAR-BIND profile) (OAUTH-PAR-BIND method)
                  (OAUTH-REV-DURABLE source) (OAUTH-REV-DURABLE profile) (OAUTH-REV-DURABLE method))
  invariant: "Token admission requires PAR binding, and once revocation intent is requested, crash-recovery never restores an active session."
  parameters: '()
  state: '((parRegistered "bool" "false")
           (sessionActive "bool" "false")
           (sessionPersisted "bool" "false")
           (revokeRequested "bool" "false")
           (revokeIntentDurable "bool" "false")
           (crashed "bool" "false")
           (revokedOnServer "bool" "false"))
  guards: '((par-request-binding (. h parRegistered))
            (durable-revoke-intent (. h revokeIntentDurable)))
  transitions:
  '((registerPar
     (action registerPar ()
       (if (and (not (. h parRegistered)) (not (. h sessionActive)) (not (. h revokeRequested)))
         (set-h (parRegistered #t))
         (keep-h))))
    (admitViaPar
     (action admitViaPar ()
       (if (and (guard par-request-binding (. h parRegistered))
                (not (. h sessionActive))
                (not (. h revokeRequested))
                (not (. h crashed)))
         (set-h (sessionActive #t) (sessionPersisted #t))
         (keep-h))))
    (requestRevokeDurable
     (action requestRevokeDurable ()
       (if (and (. h sessionActive) (not (. h revokeRequested)) (not (. h crashed)))
         (set-h (revokeRequested #t)
                (revokeIntentDurable (guard durable-revoke-intent #t #f))
                (sessionActive #f))
         (keep-h))))
    (crashHost
     (action crashHost ()
       (if (not (. h crashed))
         (set-h (crashed #t) (sessionActive #f))
         (keep-h))))
    (recoverHost
     (action recoverHost ()
       (if (. h crashed)
         (if (. h revokeIntentDurable)
           (set-h (crashed #f) (sessionActive #f) (sessionPersisted #f) (revokedOnServer #t))
           (set-h (crashed #f) (sessionActive (. h sessionPersisted))))
         (keep-h))))
    (completeRevoke
     (action completeRevoke ()
       (if (and (. h revokeIntentDurable) (not (. h crashed)) (not (. h revokedOnServer)))
         (set-h (revokedOnServer #t) (sessionActive #f) (sessionPersisted #f))
         (keep-h))))
    (step
     (action step ()
       (any registerPar admitViaPar requestRevokeDurable crashHost recoverHost completeRevoke))))
  safety:
  '(or (not (. h sessionActive))
       (and (. h parRegistered) (not (. h revokeRequested))))
  traces:
  '((checkSafe (action checkSafe () (all (assert safety) (keep-h))))
    (checkUnsafe (action checkUnsafe () (all (assert (not safety)) (keep-h))))
    (crashSafeRevocationRecoveryTest
     (run crashSafeRevocationRecoveryTest
       (then init registerPar admitViaPar requestRevokeDurable crashHost recoverHost
             (all (assert (not (. h sessionActive)))
                  (assert (. h revokedOnServer))
                  (assert safety)
                  (keep-h)))))
    (unboundParBlockedTest
     (run unboundParBlockedTest
       (then init admitViaPar
             (all (assert (not (. h sessionActive))) (assert safety) (keep-h)))))
    (crashDropsRevocationCountermodelTest
     (run crashDropsRevocationCountermodelTest
       (then init registerPar admitViaPar requestRevokeVolatile crashHost recoverHost checkUnsafe))))
  countermodels: (list CrashDropsRevocationCountermodel UnboundParExchangeCountermodel)
  limits: "Finite PAR and crash-recovery state abstraction; does not model network partitions to RFC 7009 endpoints or filesystem fsync internals.")

(.def (CrashDropsRevocationCountermodel @ OAuthRevocationRecoveryModel)
  identity: 'threat.oauth-revocation-recovery.crash-drops-revocation
  dropped-guard: 'durable-revoke-intent
  step-action: "stepCrashDropsRevocation"
  derive-from-transition: 'requestRevokeDurable
  derive-action-name: 'requestRevokeVolatile
  expected-itf-predicate: "h.sessionActive == true and h.revokeRequested == true")

(.def (UnboundParExchangeCountermodel @ OAuthRevocationRecoveryModel)
  identity: 'threat.oauth-revocation-recovery.unbound-par-exchange
  dropped-guard: 'par-request-binding
  step-action: "stepUnboundPar"
  derive-from-transition: 'admitViaPar
  derive-action-name: 'admitWithoutPar
  expected-itf-predicate: "h.sessionActive == true and not(h.parRegistered)")
