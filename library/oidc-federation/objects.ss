;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; OIDC Federation threat model (OIDC Core 1.0 §3.1.3.7 & §5.3.4 / RFC 7517 JWKS).
;;; Models asymmetric ID-token verification, multi-audience azp binding, UserInfo
;;; subject binding against token-substitution, and JWKS force-refresh cooldown.
(import :clan/poo/object
        (only-in "../authority-currentness/objects.ss" AuthorityCurrentnessModel))
(export OidcFederationModel
        SubSubstitutionCountermodel
        AzpBypassCountermodel
        JwksRefreshStormCountermodel)

(.def (OidcFederationModel @ AuthorityCurrentnessModel)
  identity: 'threat.oidc-federation
  family: 'threat.oidc-federation
  quint-module: "oidc_federation"
  quint-file: "OidcFederation.qnt"
  domain-dir: "threat/oidc-federation"
  quint-imports: '(("authority_currentness" "../authority-currentness/AuthorityCurrentness"))
  rules: '((oidc-azp-binding OIDC-AZP-BIND quint)
           (oidc-sub-binding OIDC-SUB-BIND quint)
           (oidc-jwks-cooldown OIDC-JWKS-COOL quint))
  dependencies: '((OIDC-AZP-BIND source) (OIDC-AZP-BIND profile) (OIDC-AZP-BIND method)
                  (OIDC-SUB-BIND source) (OIDC-SUB-BIND profile) (OIDC-SUB-BIND method)
                  (OIDC-JWKS-COOL source) (OIDC-JWKS-COOL profile) (OIDC-JWKS-COOL method))
  invariant: "Admitted OIDC sessions require asymmetric ID-token verification, matching azp on multi-audience tokens, exact UserInfo sub equality with the verified ID token, and bounded JWKS refresh cooldown."
  parameters: '()
  state: '((jwksEpoch "int" "1")
           (jwksRefreshes "int" "0")
           (jwksCooldown "bool" "false")
           (idTokenVerified "bool" "false")
           (idTokenSub "int" "0")
           (multiAud "bool" "false")
           (azpMatchesClient "bool" "false")
           (userInfoFetched "bool" "false")
           (userInfoSub "int" "0")
           (admitted "bool" "false")
           (unsafe "bool" "false"))
  guards: '((multi-aud-azp-binding "not(isMultiAud) or azpOk")
            (userinfo-sub-binding "h.idTokenVerified and uiSub == h.idTokenSub")
            (jwks-refresh-cooldown "not(h.jwksCooldown) and h.jwksRefreshes < 2"))
  transitions:
  '((verifyIdTokenAs "action verifyIdTokenAs(sub: int, isMultiAud: bool, azpOk: bool, algSafe: bool): bool = if (not(h.idTokenVerified) and algSafe and (not(isMultiAud) or azpOk))\n    h' = h.with(\"idTokenVerified\", true).with(\"idTokenSub\", sub).with(\"multiAud\", isMultiAud).with(\"azpMatchesClient\", azpOk)\n    else h' = h")
    (verifyIdToken "action verifyIdToken = { nondet sub = Set(1, 2).oneOf()\n    nondet isMultiAud = Set(false, true).oneOf()\n    nondet azpOk = Set(false, true).oneOf()\n    nondet algSafe = Set(false, true).oneOf()\n    verifyIdTokenAs(sub, isMultiAud, azpOk, algSafe) }")
    (fetchUserInfoAndAdmitAs "action fetchUserInfoAndAdmitAs(uiSub: int): bool = if (h.idTokenVerified and not(h.admitted) and uiSub == h.idTokenSub)\n    h' = h.with(\"userInfoFetched\", true).with(\"userInfoSub\", uiSub).with(\"admitted\", true)\n    else h' = h")
    (fetchUserInfoAndAdmit "action fetchUserInfoAndAdmit = { nondet uiSub = Set(1, 2).oneOf()\n    fetchUserInfoAndAdmitAs(uiSub) }")
    (refreshJwks "action refreshJwks = if (not(h.jwksCooldown) and h.jwksRefreshes < 2)\n    h' = h.with(\"jwksEpoch\", h.jwksEpoch + 1).with(\"jwksRefreshes\", h.jwksRefreshes + 1).with(\"jwksCooldown\", true)\n    else h' = h")
    (cooldownTick "action cooldownTick = if (h.jwksCooldown)\n    h' = h.with(\"jwksCooldown\", false)\n    else h' = h")
    (step "action step = any { verifyIdToken, fetchUserInfoAndAdmit, refreshJwks, cooldownTick }"))
  safety: "not(h.unsafe) and (not(h.admitted) or (h.idTokenVerified and h.userInfoSub == h.idTokenSub and (not(h.multiAud) or h.azpMatchesClient))) and h.jwksRefreshes <= 2"
  traces:
  '((checkSafe "action checkSafe = all { assert(safety), h' = h }")
    (checkUnsafe "action checkUnsafe = all { assert(not(safety)), h' = h }")
    (validOidcFederationTest "run validOidcFederationTest = init.then(verifyIdTokenAs(1, true, true, true)).then(fetchUserInfoAndAdmitAs(1)).then(all { assert(h.admitted), assert(safety), h' = h })")
    (mismatchedUserInfoSubRejectedTest "run mismatchedUserInfoSubRejectedTest = init.then(verifyIdTokenAs(1, false, false, true)).then(fetchUserInfoAndAdmitAs(2)).then(all { assert(not(h.admitted)), assert(safety), h' = h })")
    (multiAudMissingAzpRejectedTest "run multiAudMissingAzpRejectedTest = init.then(verifyIdTokenAs(1, true, false, true)).then(all { assert(not(h.idTokenVerified)), assert(safety), h' = h })")
    (jwksCooldownEnforcedTest "run jwksCooldownEnforcedTest = init.then(refreshJwks).then(refreshJwks).then(all { assert(h.jwksRefreshes == 1), assert(safety), h' = h })")
    (subSubstitutionCountermodelTest "run subSubstitutionCountermodelTest = init.then(verifyIdTokenAs(1, false, false, true)).then(fetchUserInfoNoSubCheck).then(checkUnsafe)"))
  countermodels: (list SubSubstitutionCountermodel AzpBypassCountermodel JwksRefreshStormCountermodel)
  limits: "Finite OIDC Federation protocol abstraction; does not model RSA/ECDSA/EdDSA signature mathematics, TLS certificate validation, or IdP internal key storage.")

(.def (SubSubstitutionCountermodel @ OidcFederationModel)
  identity: 'threat.oidc-federation.sub-substitution
  dropped-guard: 'userinfo-sub-binding
  step-action: "stepSubSubstitution"
  counter-action: "action fetchUserInfoNoSubCheck = if (h.idTokenVerified and not(h.admitted))\n    h' = h.with(\"userInfoFetched\", true).with(\"userInfoSub\", h.idTokenSub + 1).with(\"admitted\", true).with(\"unsafe\", true)\n    else h' = h\n  action stepSubSubstitution = any { step, fetchUserInfoNoSubCheck }"
  expected-itf-predicate: "h.admitted == true and h.userInfoSub != h.idTokenSub")

(.def (AzpBypassCountermodel @ OidcFederationModel)
  identity: 'threat.oidc-federation.azp-bypass
  dropped-guard: 'multi-aud-azp-binding
  step-action: "stepAzpBypass"
  counter-action: "action verifyIdTokenNoAzp = if (not(h.idTokenVerified))\n    h' = h.with(\"idTokenVerified\", true).with(\"idTokenSub\", 1).with(\"multiAud\", true).with(\"azpMatchesClient\", false).with(\"unsafe\", true)\n    else h' = h\n  action stepAzpBypass = any { step, verifyIdTokenNoAzp }"
  expected-itf-predicate: "h.multiAud == true and not(h.azpMatchesClient)")

(.def (JwksRefreshStormCountermodel @ OidcFederationModel)
  identity: 'threat.oidc-federation.jwks-refresh-storm
  dropped-guard: 'jwks-refresh-cooldown
  step-action: "stepJwksStorm"
  counter-action: "action refreshJwksUnthrottled = h' = h.with(\"jwksRefreshes\", h.jwksRefreshes + 1).with(\"unsafe\", h.unsafe or h.jwksRefreshes >= 2)\n  action stepJwksStorm = any { step, refreshJwksUnthrottled }"
  expected-itf-predicate: "h.jwksRefreshes > 2")
