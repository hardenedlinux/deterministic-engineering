// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.oauth-revocation-recovery
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel durable-revoke-intent step=stepCrashDropsRevocation max-steps=6 itf="h.sessionActive == true and h.revokeRequested == true"
// @countermodel par-request-binding step=stepUnboundPar max-steps=6 itf="h.sessionActive == true and not(h.parRegistered)"
// Limits: Finite PAR and crash-recovery state abstraction; does not model network partitions to RFC 7009 endpoints or filesystem fsync internals.
module oauth_revocation_recovery {
  import authority_currentness.* from "../authority-currentness/AuthorityCurrentness"
  type State = { parRegistered: bool, sessionActive: bool, sessionPersisted: bool, revokeRequested: bool, revokeIntentDurable: bool, crashed: bool, revokedOnServer: bool }
  var h: State
  action init = h' = { parRegistered: false, sessionActive: false, sessionPersisted: false, revokeRequested: false, revokeIntentDurable: false, crashed: false, revokedOnServer: false }
  action registerPar = if ((not(h.parRegistered) and not(h.sessionActive) and not(h.revokeRequested))) h' = h.with("parRegistered", true) else h' = h
  action admitViaPar = if ((h.parRegistered and not(h.sessionActive) and not(h.revokeRequested) and not(h.crashed))) h' = h.with("sessionActive", true).with("sessionPersisted", true) else h' = h
  action requestRevokeDurable = if ((h.sessionActive and not(h.revokeRequested) and not(h.crashed))) h' = h.with("revokeRequested", true).with("revokeIntentDurable", true).with("sessionActive", false) else h' = h
  action crashHost = if (not(h.crashed)) h' = h.with("crashed", true).with("sessionActive", false) else h' = h
  action recoverHost = if (h.crashed) if (h.revokeIntentDurable) h' = h.with("crashed", false).with("sessionActive", false).with("sessionPersisted", false).with("revokedOnServer", true) else h' = h.with("crashed", false).with("sessionActive", h.sessionPersisted) else h' = h
  action completeRevoke = if ((h.revokeIntentDurable and not(h.crashed) and not(h.revokedOnServer))) h' = h.with("revokedOnServer", true).with("sessionActive", false).with("sessionPersisted", false) else h' = h
  action step = any { registerPar, admitViaPar, requestRevokeDurable, crashHost, recoverHost, completeRevoke }
  val safety = (not(h.sessionActive) or (h.parRegistered and not(h.revokeRequested)))
  // Countermodel threat.oauth-revocation-recovery.crash-drops-revocation (dropped guard: durable-revoke-intent)
  action requestRevokeVolatile = if ((h.sessionActive and not(h.revokeRequested) and not(h.crashed))) h' = h.with("revokeRequested", true).with("revokeIntentDurable", false).with("sessionActive", false) else h' = h
  action stepCrashDropsRevocation = any { step, requestRevokeVolatile }
  // Countermodel threat.oauth-revocation-recovery.unbound-par-exchange (dropped guard: par-request-binding)
  action admitWithoutPar = if ((true and not(h.sessionActive) and not(h.revokeRequested) and not(h.crashed))) h' = h.with("sessionActive", true).with("sessionPersisted", true) else h' = h
  action stepUnboundPar = any { step, admitWithoutPar }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run crashSafeRevocationRecoveryTest = init.then(registerPar).then(admitViaPar).then(requestRevokeDurable).then(crashHost).then(recoverHost).then(all { assert(not(h.sessionActive)), assert(h.revokedOnServer), assert(safety), h' = h })
  run unboundParBlockedTest = init.then(admitViaPar).then(all { assert(not(h.sessionActive)), assert(safety), h' = h })
  run crashDropsRevocationCountermodelTest = init.then(registerPar).then(admitViaPar).then(requestRevokeVolatile).then(crashHost).then(recoverHost).then(checkUnsafe)
}
