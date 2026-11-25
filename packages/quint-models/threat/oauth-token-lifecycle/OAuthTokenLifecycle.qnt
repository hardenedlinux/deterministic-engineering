// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// Projected from Scheme POO module threat.oauth-token-lifecycle. Do not edit by hand.
// Limits: Finite OAuth 2.1 lifecycle abstraction; does not model TLS, JWT signature cryptography, or IdP internal storage.
module oauth_token_lifecycle {
  import authority_currentness.* from "../authority-currentness/AuthorityCurrentness"
  type State = { authEpoch: int, codeIssued: bool, codeConsumed: bool, signedIn: bool, vaultHasToken: bool, refreshInFlight: bool, refreshStartedEpoch: int, revoked: bool, grantedScopeLevel: int, activeScopeLevel: int, exchanges: int, unsafe: bool }
  var h: State
  action init = h' = { authEpoch: 0, codeIssued: false, codeConsumed: false, signedIn: false, vaultHasToken: false, refreshInFlight: false, refreshStartedEpoch: 0, revoked: false, grantedScopeLevel: 1, activeScopeLevel: 0, exchanges: 0, unsafe: false }
  action beginOAuth = if (not(h.codeIssued) and h.authEpoch < 3)
    h' = h.with("codeIssued", true).with("codeConsumed", false)
    else h' = h
  action completeCallbackAs(pkceOk: bool, nonceOk: bool): bool = if (h.codeIssued and not(h.codeConsumed) and pkceOk and nonceOk and h.authEpoch < 3)
    h' = h.with("codeConsumed", true).with("signedIn", true).with("vaultHasToken", true)
      .with("revoked", false).with("authEpoch", h.authEpoch + 1)
      .with("activeScopeLevel", h.grantedScopeLevel).with("exchanges", h.exchanges + 1)
    else h' = h
  action completeCallback = { nondet pkceOk = Set(false, true).oneOf()
    nondet nonceOk = Set(false, true).oneOf()
    completeCallbackAs(pkceOk, nonceOk) }
  action startRefresh = if (h.signedIn and h.vaultHasToken and not(h.refreshInFlight))
    h' = h.with("refreshInFlight", true).with("refreshStartedEpoch", h.authEpoch)
    else h' = h
  action finishRefreshAs(newScope: int): bool = if (h.refreshInFlight)
    if (epochCurrent(h.authEpoch, h.refreshStartedEpoch) and h.signedIn and not(h.revoked) and newScope <= h.grantedScopeLevel)
      h' = h.with("refreshInFlight", false).with("vaultHasToken", true).with("activeScopeLevel", newScope)
    else h' = h.with("refreshInFlight", false)
    else h' = h
  action finishRefresh = { nondet newScope = Set(1, 2).oneOf()
    finishRefreshAs(newScope) }
  action signOut = if (h.signedIn and h.authEpoch < 3)
    h' = h.with("signedIn", false).with("vaultHasToken", false).with("revoked", true)
      .with("activeScopeLevel", 0).with("authEpoch", h.authEpoch + 1)
    else h' = h
  action step = any { beginOAuth, completeCallback, startRefresh, finishRefresh, signOut }
  val safety = not(h.unsafe) and (h.signedIn or not(h.vaultHasToken)) and h.activeScopeLevel <= h.grantedScopeLevel and h.exchanges <= 1
  // Countermodel threat.oauth-token-lifecycle.code-replay (dropped guard: single-use-code)
  action replayCode = if (h.codeIssued and h.codeConsumed)
    h' = h.with("exchanges", h.exchanges + 1).with("unsafe", true)
    else h' = h
  action stepCodeReplay = any { step, replayCode }
  // Countermodel threat.oauth-token-lifecycle.zombie-refresh (dropped guard: refresh-epoch-currency)
  action finishRefreshZombie = if (h.refreshInFlight)
    h' = h.with("refreshInFlight", false).with("vaultHasToken", true)
      .with("unsafe", h.unsafe or not(h.signedIn) or h.revoked or not(epochCurrent(h.authEpoch, h.refreshStartedEpoch)))
    else h' = h
  action stepZombieRefresh = any { step, finishRefreshZombie }
  // Countermodel threat.oauth-token-lifecycle.scope-escalation (dropped guard: scope-monotonicity)
  action finishRefreshEscalated = if (h.refreshInFlight and h.signedIn)
    h' = h.with("refreshInFlight", false).with("activeScopeLevel", h.grantedScopeLevel + 1).with("unsafe", true)
    else h' = h
  action stepScopeEscalation = any { step, finishRefreshEscalated }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run validLoginAndRefreshTest = init.then(beginOAuth).then(completeCallbackAs(true, true)).then(startRefresh).then(finishRefreshAs(1)).then(all { assert(h.vaultHasToken), assert(safety), h' = h })
  run signOutBlocksInFlightRefreshTest = init.then(beginOAuth).then(completeCallbackAs(true, true)).then(startRefresh).then(signOut).then(finishRefreshAs(1)).then(all { assert(not(h.vaultHasToken)), assert(not(h.signedIn)), assert(safety), h' = h })
  run escalatedRefreshRejectedTest = init.then(beginOAuth).then(completeCallbackAs(true, true)).then(startRefresh).then(finishRefreshAs(2)).then(all { assert(h.activeScopeLevel == 1), assert(safety), h' = h })
  run zombieRefreshCountermodelTest = init.then(beginOAuth).then(completeCallbackAs(true, true)).then(startRefresh).then(signOut).then(finishRefreshZombie).then(checkUnsafe)
}
