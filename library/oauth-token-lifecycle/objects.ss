;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; OAuth 2.1 token lifecycle threat model (RFC 9700 / PKCE S256 / RTR / Epoch Currency).
;;; Models single-use code exchange, refresh-vs-signout epoch currency, and scope monotonicity.
(import :clan/poo/object
        (only-in "../authority-currentness/objects.ss" AuthorityCurrentnessModel))
(export OAuthTokenLifecycleModel
        CodeReplayCountermodel
        ZombieRefreshCountermodel
        ScopeEscalationCountermodel)

(.def (OAuthTokenLifecycleModel @ AuthorityCurrentnessModel)
  identity: 'threat.oauth-token-lifecycle
  family: 'threat.oauth-token-lifecycle
  quint-module: "oauth_token_lifecycle"
  quint-file: "OAuthTokenLifecycle.qnt"
  domain-dir: "threat/oauth-token-lifecycle"
  quint-imports: '(("authority_currentness" "../authority-currentness/AuthorityCurrentness"))
  rules: '((oauth-code-once OAUTH-CODE-ONCE quint)
           (oauth-refresh-epoch OAUTH-REF-EPOCH quint)
           (oauth-scope-mono OAUTH-SCOPE-MONO quint))
  dependencies: '((OAUTH-CODE-ONCE source) (OAUTH-CODE-ONCE profile) (OAUTH-CODE-ONCE method)
                  (OAUTH-REF-EPOCH source) (OAUTH-REF-EPOCH profile) (OAUTH-REF-EPOCH method)
                  (OAUTH-SCOPE-MONO source) (OAUTH-SCOPE-MONO profile) (OAUTH-SCOPE-MONO method))
  invariant: "Authorization codes are single-use with PKCE+nonce, refresh never resurrects a signed-out/revoked vault entry, and refreshed scopes never escalate beyond granted scopes."
  parameters: '()
  state: '((authEpoch "int" "0")
           (codeIssued "bool" "false")
           (codeConsumed "bool" "false")
           (signedIn "bool" "false")
           (vaultHasToken "bool" "false")
           (refreshInFlight "bool" "false")
           (refreshStartedEpoch "int" "0")
           (revoked "bool" "false")
           (grantedScopeLevel "int" "1")
           (activeScopeLevel "int" "0")
           (exchanges "int" "0")
           (unsafe "bool" "false"))
  guards: '((single-use-code "h.codeIssued and not(h.codeConsumed)")
            (refresh-epoch-currency "epochCurrent(h.authEpoch, h.refreshStartedEpoch) and h.signedIn and not(h.revoked)")
            (scope-monotonicity "newScope <= h.grantedScopeLevel"))
  transitions:
  '((beginOAuth "action beginOAuth = if (not(h.codeIssued) and h.authEpoch < 3)\n    h' = h.with(\"codeIssued\", true).with(\"codeConsumed\", false)\n    else h' = h")
    (completeCallbackAs "action completeCallbackAs(pkceOk: bool, nonceOk: bool): bool = if (h.codeIssued and not(h.codeConsumed) and pkceOk and nonceOk and h.authEpoch < 3)\n    h' = h.with(\"codeConsumed\", true).with(\"signedIn\", true).with(\"vaultHasToken\", true)\n      .with(\"revoked\", false).with(\"authEpoch\", h.authEpoch + 1)\n      .with(\"activeScopeLevel\", h.grantedScopeLevel).with(\"exchanges\", h.exchanges + 1)\n    else h' = h")
    (completeCallback "action completeCallback = { nondet pkceOk = Set(false, true).oneOf()\n    nondet nonceOk = Set(false, true).oneOf()\n    completeCallbackAs(pkceOk, nonceOk) }")
    (startRefresh "action startRefresh = if (h.signedIn and h.vaultHasToken and not(h.refreshInFlight))\n    h' = h.with(\"refreshInFlight\", true).with(\"refreshStartedEpoch\", h.authEpoch)\n    else h' = h")
    (finishRefreshAs "action finishRefreshAs(newScope: int): bool = if (h.refreshInFlight)\n    if (epochCurrent(h.authEpoch, h.refreshStartedEpoch) and h.signedIn and not(h.revoked) and newScope <= h.grantedScopeLevel)\n      h' = h.with(\"refreshInFlight\", false).with(\"vaultHasToken\", true).with(\"activeScopeLevel\", newScope)\n    else h' = h.with(\"refreshInFlight\", false)\n    else h' = h")
    (finishRefresh "action finishRefresh = { nondet newScope = Set(1, 2).oneOf()\n    finishRefreshAs(newScope) }")
    (signOut "action signOut = if (h.signedIn and h.authEpoch < 3)\n    h' = h.with(\"signedIn\", false).with(\"vaultHasToken\", false).with(\"revoked\", true)\n      .with(\"activeScopeLevel\", 0).with(\"authEpoch\", h.authEpoch + 1)\n    else h' = h")
    (step "action step = any { beginOAuth, completeCallback, startRefresh, finishRefresh, signOut }"))
  safety: "not(h.unsafe) and (h.signedIn or not(h.vaultHasToken)) and h.activeScopeLevel <= h.grantedScopeLevel and h.exchanges <= 1"
  traces:
  '((checkSafe "action checkSafe = all { assert(safety), h' = h }")
    (checkUnsafe "action checkUnsafe = all { assert(not(safety)), h' = h }")
    (validLoginAndRefreshTest "run validLoginAndRefreshTest = init.then(beginOAuth).then(completeCallbackAs(true, true)).then(startRefresh).then(finishRefreshAs(1)).then(all { assert(h.vaultHasToken), assert(safety), h' = h })")
    (signOutBlocksInFlightRefreshTest "run signOutBlocksInFlightRefreshTest = init.then(beginOAuth).then(completeCallbackAs(true, true)).then(startRefresh).then(signOut).then(finishRefreshAs(1)).then(all { assert(not(h.vaultHasToken)), assert(not(h.signedIn)), assert(safety), h' = h })")
    (escalatedRefreshRejectedTest "run escalatedRefreshRejectedTest = init.then(beginOAuth).then(completeCallbackAs(true, true)).then(startRefresh).then(finishRefreshAs(2)).then(all { assert(h.activeScopeLevel == 1), assert(safety), h' = h })")
    (zombieRefreshCountermodelTest "run zombieRefreshCountermodelTest = init.then(beginOAuth).then(completeCallbackAs(true, true)).then(startRefresh).then(signOut).then(finishRefreshZombie).then(checkUnsafe)"))
  countermodels: (list CodeReplayCountermodel ZombieRefreshCountermodel ScopeEscalationCountermodel)
  limits: "Finite OAuth 2.1 lifecycle abstraction; does not model TLS, JWT signature cryptography, or IdP internal storage.")

(.def (CodeReplayCountermodel @ OAuthTokenLifecycleModel)
  identity: 'threat.oauth-token-lifecycle.code-replay
  dropped-guard: 'single-use-code
  step-action: "stepCodeReplay"
  counter-action: "action replayCode = if (h.codeIssued and h.codeConsumed)\n    h' = h.with(\"exchanges\", h.exchanges + 1).with(\"unsafe\", true)\n    else h' = h\n  action stepCodeReplay = any { step, replayCode }"
  expected-itf-predicate: "h.unsafe == true and h.exchanges >= 2")

(.def (ZombieRefreshCountermodel @ OAuthTokenLifecycleModel)
  identity: 'threat.oauth-token-lifecycle.zombie-refresh
  dropped-guard: 'refresh-epoch-currency
  step-action: "stepZombieRefresh"
  counter-action: "action finishRefreshZombie = if (h.refreshInFlight)\n    h' = h.with(\"refreshInFlight\", false).with(\"vaultHasToken\", true)\n      .with(\"unsafe\", h.unsafe or not(h.signedIn) or h.revoked or not(epochCurrent(h.authEpoch, h.refreshStartedEpoch)))\n    else h' = h\n  action stepZombieRefresh = any { step, finishRefreshZombie }"
  expected-itf-predicate: "h.vaultHasToken == true and not(h.signedIn)")

(.def (ScopeEscalationCountermodel @ OAuthTokenLifecycleModel)
  identity: 'threat.oauth-token-lifecycle.scope-escalation
  dropped-guard: 'scope-monotonicity
  step-action: "stepScopeEscalation"
  counter-action: "action finishRefreshEscalated = if (h.refreshInFlight and h.signedIn)\n    h' = h.with(\"refreshInFlight\", false).with(\"activeScopeLevel\", h.grantedScopeLevel + 1).with(\"unsafe\", true)\n    else h' = h\n  action stepScopeEscalation = any { step, finishRefreshEscalated }"
  expected-itf-predicate: "h.activeScopeLevel > h.grantedScopeLevel")
