;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; OAuth PAR + Crash-Safe Revocation Recovery threat model (RFC 9126 / RFC 7009).
;;; Models PAR request-URI binding and durable revocation-intent journaling so a
;;; host crash mid-signout never resurrects an active token on recovery.
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
           (revokeRequested "bool" "false")
           (revokeIntentDurable "bool" "false")
           (crashed "bool" "false")
           (revokedOnServer "bool" "false")
           (unsafe "bool" "false"))
  guards: '((par-request-binding "h.parRegistered")
            (durable-revoke-intent "h.revokeIntentDurable"))
  transitions:
  '((registerPar "action registerPar = if (not(h.parRegistered) and not(h.sessionActive) and not(h.revokeRequested))\n    h' = h.with(\"parRegistered\", true)\n    else h' = h")
    (admitViaPar "action admitViaPar = if (h.parRegistered and not(h.sessionActive) and not(h.revokeRequested) and not(h.crashed))\n    h' = h.with(\"sessionActive\", true)\n    else h' = h")
    (requestRevokeDurable "action requestRevokeDurable = if (h.sessionActive and not(h.revokeRequested) and not(h.crashed))\n    h' = h.with(\"revokeRequested\", true).with(\"revokeIntentDurable\", true).with(\"sessionActive\", false)\n    else h' = h")
    (crashHost "action crashHost = if (not(h.crashed))\n    h' = h.with(\"crashed\", true)\n    else h' = h")
    (recoverHost "action recoverHost = if (h.crashed)\n    if (h.revokeIntentDurable)\n      h' = h.with(\"crashed\", false).with(\"sessionActive\", false).with(\"revokedOnServer\", true)\n    else h' = h.with(\"crashed\", false)\n    else h' = h")
    (completeRevoke "action completeRevoke = if (h.revokeIntentDurable and not(h.crashed) and not(h.revokedOnServer))\n    h' = h.with(\"revokedOnServer\", true).with(\"sessionActive\", false)\n    else h' = h")
    (step "action step = any { registerPar, admitViaPar, requestRevokeDurable, crashHost, recoverHost, completeRevoke }"))
  safety: "not(h.unsafe) and (not(h.sessionActive) or (h.parRegistered and not(h.revokeRequested)))"
  traces:
  '((checkSafe "action checkSafe = all { assert(safety), h' = h }")
    (checkUnsafe "action checkUnsafe = all { assert(not(safety)), h' = h }")
    (crashSafeRevocationRecoveryTest "run crashSafeRevocationRecoveryTest = init.then(registerPar).then(admitViaPar).then(requestRevokeDurable).then(crashHost).then(recoverHost).then(all { assert(not(h.sessionActive)), assert(h.revokedOnServer), assert(safety), h' = h })")
    (unboundParBlockedTest "run unboundParBlockedTest = init.then(admitViaPar).then(all { assert(not(h.sessionActive)), assert(safety), h' = h })")
    (crashDropsRevocationCountermodelTest "run crashDropsRevocationCountermodelTest = init.then(registerPar).then(admitViaPar).then(requestRevokeVolatile).then(crashHost).then(recoverVolatile).then(checkUnsafe)"))
  countermodels: (list CrashDropsRevocationCountermodel UnboundParExchangeCountermodel)
  limits: "Finite PAR and crash-recovery state abstraction; does not model network partitions to RFC 7009 endpoints or filesystem fsync internals.")

(.def (CrashDropsRevocationCountermodel @ OAuthRevocationRecoveryModel)
  identity: 'threat.oauth-revocation-recovery.crash-drops-revocation
  dropped-guard: 'durable-revoke-intent
  step-action: "stepCrashDropsRevocation"
  counter-action: "action requestRevokeVolatile = if (h.sessionActive and not(h.revokeRequested) and not(h.crashed))\n    h' = h.with(\"revokeRequested\", true).with(\"revokeIntentDurable\", false)\n    else h' = h\n  action recoverVolatile = if (h.crashed and h.revokeRequested and not(h.revokeIntentDurable))\n    h' = h.with(\"crashed\", false).with(\"sessionActive\", true).with(\"unsafe\", true)\n    else h' = h\n  action stepCrashDropsRevocation = any { step, requestRevokeVolatile, recoverVolatile }"
  expected-itf-predicate: "h.sessionActive == true and h.revokeRequested == true")

(.def (UnboundParExchangeCountermodel @ OAuthRevocationRecoveryModel)
  identity: 'threat.oauth-revocation-recovery.unbound-par-exchange
  dropped-guard: 'par-request-binding
  step-action: "stepUnboundPar"
  counter-action: "action admitWithoutPar = if (not(h.parRegistered) and not(h.sessionActive))\n    h' = h.with(\"sessionActive\", true).with(\"unsafe\", true)\n    else h' = h\n  action stepUnboundPar = any { step, admitWithoutPar }"
  expected-itf-predicate: "h.sessionActive == true and not(h.parRegistered)")
