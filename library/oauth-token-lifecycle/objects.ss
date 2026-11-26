;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; OAuth 2.1 token lifecycle threat model (RFC 9700 / PKCE S256 / RTR / Epoch Currency).
;;; Emergent safety (zero synthetic unsafe flag); all 3 countermodels auto-derived via (guard ...).
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
           (exchanges "int" "0"))
  guards: '((single-use-code (and (. h codeIssued) (not (. h codeConsumed))))
            (refresh-epoch-currency (and (call epochCurrent (. h authEpoch) (. h refreshStartedEpoch))
                                         (. h signedIn) (not (. h revoked))))
            (scope-monotonicity (<= newScope (. h grantedScopeLevel))))
  transitions:
  '((beginOAuth
     (action beginOAuth ()
       (if (and (not (. h codeIssued)) (< (. h authEpoch) 3))
         (set-h (codeIssued #t) (codeConsumed #f))
         (keep-h))))
    (completeCallbackAs
     (action completeCallbackAs ((pkceOk "bool") (nonceOk "bool")) "bool"
       (if (and (. h codeIssued)
                (guard single-use-code (not (. h codeConsumed)))
                pkceOk nonceOk
                (< (. h authEpoch) 3))
         (set-h (codeConsumed #t)
                (signedIn #t)
                (vaultHasToken #t)
                (revoked #f)
                (authEpoch (+ (. h authEpoch) 1))
                (activeScopeLevel (. h grantedScopeLevel))
                (exchanges (+ (. h exchanges) 1)))
         (keep-h))))
    (completeCallback
     (action completeCallback ()
       (nondet ((pkceOk (set #f #t)) (nonceOk (set #f #t)))
         (call completeCallbackAs pkceOk nonceOk))))
    (startRefresh
     (action startRefresh ()
       (if (and (. h signedIn) (. h vaultHasToken) (not (. h refreshInFlight)))
         (set-h (refreshInFlight #t) (refreshStartedEpoch (. h authEpoch)))
         (keep-h))))
    (finishRefreshAs
     (action finishRefreshAs ((newScope "int")) "bool"
       (if (. h refreshInFlight)
         (if (and (guard refresh-epoch-currency
                         (and (call epochCurrent (. h authEpoch) (. h refreshStartedEpoch))
                              (. h signedIn)
                              (not (. h revoked))))
                  (guard scope-monotonicity (<= newScope (. h grantedScopeLevel))))
           (set-h (refreshInFlight #f) (vaultHasToken #t) (activeScopeLevel newScope))
           (set-h (refreshInFlight #f)))
         (keep-h))))
    (finishRefresh
     (action finishRefresh ()
       (nondet ((newScope (set 1 2)))
         (call finishRefreshAs newScope))))
    (signOut
     (action signOut ()
       (if (and (. h signedIn) (< (. h authEpoch) 3))
         (set-h (signedIn #f)
                (vaultHasToken #f)
                (revoked #t)
                (activeScopeLevel 0)
                (authEpoch (+ (. h authEpoch) 1)))
         (keep-h))))
    (step
     (action step ()
       (any beginOAuth completeCallback startRefresh finishRefresh signOut))))
  safety:
  '(and (or (. h signedIn) (not (. h vaultHasToken)))
        (<= (. h activeScopeLevel) (. h grantedScopeLevel))
        (<= (. h exchanges) 1))
  traces:
  '((checkSafe (action checkSafe () (all (assert safety) (keep-h))))
    (checkUnsafe (action checkUnsafe () (all (assert (not safety)) (keep-h))))
    (validLoginAndRefreshTest
     (run validLoginAndRefreshTest
       (then init beginOAuth (call completeCallbackAs #t #t) startRefresh (call finishRefreshAs 1)
             (all (assert (. h vaultHasToken)) (assert safety) (keep-h)))))
    (signOutBlocksInFlightRefreshTest
     (run signOutBlocksInFlightRefreshTest
       (then init beginOAuth (call completeCallbackAs #t #t) startRefresh signOut (call finishRefreshAs 1)
             (all (assert (not (. h vaultHasToken))) (assert (not (. h signedIn))) (assert safety) (keep-h)))))
    (escalatedRefreshRejectedTest
     (run escalatedRefreshRejectedTest
       (then init beginOAuth (call completeCallbackAs #t #t) startRefresh (call finishRefreshAs 2)
             (all (assert (= (. h activeScopeLevel) 1)) (assert safety) (keep-h)))))
    (zombieRefreshCountermodelTest
     (run zombieRefreshCountermodelTest
       (then init beginOAuth (call completeCallbackAs #t #t) startRefresh signOut (call finishRefreshZombie 1) checkUnsafe))))
  countermodels: (list CodeReplayCountermodel ZombieRefreshCountermodel ScopeEscalationCountermodel)
  limits: "Finite OAuth 2.1 lifecycle abstraction; does not model TLS, JWT signature cryptography, or IdP internal storage.")

(.def (CodeReplayCountermodel @ OAuthTokenLifecycleModel)
  identity: 'threat.oauth-token-lifecycle.code-replay
  dropped-guard: 'single-use-code
  step-action: "stepCodeReplay"
  derive-from-transition: 'completeCallbackAs
  derive-action-name: 'completeCallbackReplay
  derive-step-call: '(nondet ((pkceOk (set #f #t)) (nonceOk (set #f #t))) (call completeCallbackReplay pkceOk nonceOk))
  expected-itf-predicate: "h.exchanges >= 2")

(.def (ZombieRefreshCountermodel @ OAuthTokenLifecycleModel)
  identity: 'threat.oauth-token-lifecycle.zombie-refresh
  dropped-guard: 'refresh-epoch-currency
  step-action: "stepZombieRefresh"
  derive-from-transition: 'finishRefreshAs
  derive-action-name: 'finishRefreshZombie
  derive-step-call: '(nondet ((newScope (set 1 2))) (call finishRefreshZombie newScope))
  expected-itf-predicate: "h.vaultHasToken == true and not(h.signedIn)")

(.def (ScopeEscalationCountermodel @ OAuthTokenLifecycleModel)
  identity: 'threat.oauth-token-lifecycle.scope-escalation
  dropped-guard: 'scope-monotonicity
  step-action: "stepScopeEscalation"
  derive-from-transition: 'finishRefreshAs
  derive-action-name: 'finishRefreshEscalated
  derive-step-call: '(nondet ((newScope (set 1 2))) (call finishRefreshEscalated newScope))
  expected-itf-predicate: "h.activeScopeLevel > h.grantedScopeLevel")
