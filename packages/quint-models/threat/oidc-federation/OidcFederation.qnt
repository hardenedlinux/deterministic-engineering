// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.oidc-federation
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel userinfo-sub-binding step=stepSubSubstitution max-steps=6 itf="h.admitted == true and h.userInfoSub != h.idTokenSub"
// @countermodel multi-aud-azp-binding step=stepAzpBypass max-steps=6 itf="h.admitted == true and h.multiAud == true and not(h.azpMatchesClient)"
// @countermodel jwks-refresh-cooldown step=stepJwksStorm max-steps=6 itf="h.jwksRefreshes > 2"
// Limits: Finite OIDC Federation protocol abstraction; does not model RSA/ECDSA/EdDSA signature mathematics, TLS certificate validation, or IdP internal key storage.
module oidc_federation {
  import authority_currentness.* from "../authority-currentness/AuthorityCurrentness"
  type State = { jwksEpoch: int, jwksRefreshes: int, jwksCooldown: bool, idTokenVerified: bool, idTokenSub: int, multiAud: bool, azpMatchesClient: bool, userInfoFetched: bool, userInfoSub: int, admitted: bool }
  var h: State
  action init = h' = { jwksEpoch: 1, jwksRefreshes: 0, jwksCooldown: false, idTokenVerified: false, idTokenSub: 0, multiAud: false, azpMatchesClient: false, userInfoFetched: false, userInfoSub: 0, admitted: false }
  action verifyIdTokenAs(sub: int, isMultiAud: bool, azpOk: bool, algSafe: bool): bool = if ((not(h.idTokenVerified) and algSafe and (not(isMultiAud) or azpOk))) h' = h.with("idTokenVerified", true).with("idTokenSub", sub).with("multiAud", isMultiAud).with("azpMatchesClient", azpOk) else h' = h
  action verifyIdToken = { nondet sub = Set(1, 2).oneOf()
    nondet isMultiAud = Set(false, true).oneOf()
    nondet azpOk = Set(false, true).oneOf()
    nondet algSafe = Set(false, true).oneOf()
    verifyIdTokenAs(sub, isMultiAud, azpOk, algSafe) }
  action fetchUserInfoAndAdmitAs(uiSub: int): bool = if ((h.idTokenVerified and not(h.admitted) and uiSub == h.idTokenSub)) h' = h.with("userInfoFetched", true).with("userInfoSub", uiSub).with("admitted", true) else h' = h
  action fetchUserInfoAndAdmit = { nondet uiSub = Set(1, 2).oneOf()
    fetchUserInfoAndAdmitAs(uiSub) }
  action refreshJwks = if ((not(h.jwksCooldown) and h.jwksRefreshes < 2)) h' = h.with("jwksEpoch", (h.jwksEpoch + 1)).with("jwksRefreshes", (h.jwksRefreshes + 1)).with("jwksCooldown", true) else h' = h
  action cooldownTick = if (h.jwksCooldown) h' = h.with("jwksCooldown", false) else h' = h
  action step = any { verifyIdToken, fetchUserInfoAndAdmit, refreshJwks, cooldownTick }
  val safety = ((not(h.admitted) or (h.idTokenVerified and h.userInfoSub == h.idTokenSub and (not(h.multiAud) or h.azpMatchesClient))) and h.jwksRefreshes <= 2)
  // Countermodel threat.oidc-federation.sub-substitution (dropped guard: userinfo-sub-binding)
  action fetchUserInfoNoSubCheck(uiSub: int): bool = if ((h.idTokenVerified and not(h.admitted) and true)) h' = h.with("userInfoFetched", true).with("userInfoSub", uiSub).with("admitted", true) else h' = h
  action stepSubSubstitution = any { step, { nondet uiSub = Set(1, 2).oneOf()
    fetchUserInfoNoSubCheck(uiSub) } }
  // Countermodel threat.oidc-federation.azp-bypass (dropped guard: multi-aud-azp-binding)
  action verifyIdTokenNoAzp(sub: int, isMultiAud: bool, azpOk: bool, algSafe: bool): bool = if ((not(h.idTokenVerified) and algSafe and true)) h' = h.with("idTokenVerified", true).with("idTokenSub", sub).with("multiAud", isMultiAud).with("azpMatchesClient", azpOk) else h' = h
  action stepAzpBypass = any { step, { nondet sub = Set(1, 2).oneOf()
    nondet isMultiAud = Set(false, true).oneOf()
    nondet azpOk = Set(false, true).oneOf()
    nondet algSafe = Set(false, true).oneOf()
    verifyIdTokenNoAzp(sub, isMultiAud, azpOk, algSafe) } }
  // Countermodel threat.oidc-federation.jwks-refresh-storm (dropped guard: jwks-refresh-cooldown)
  action refreshJwksUnthrottled = if (true) h' = h.with("jwksEpoch", (h.jwksEpoch + 1)).with("jwksRefreshes", (h.jwksRefreshes + 1)).with("jwksCooldown", true) else h' = h
  action stepJwksStorm = any { step, refreshJwksUnthrottled }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run validOidcFederationTest = init.then(verifyIdTokenAs(1, true, true, true)).then(fetchUserInfoAndAdmitAs(1)).then(all { assert(h.admitted), assert(safety), h' = h })
  run mismatchedUserInfoSubRejectedTest = init.then(verifyIdTokenAs(1, false, false, true)).then(fetchUserInfoAndAdmitAs(2)).then(all { assert(not(h.admitted)), assert(safety), h' = h })
  run multiAudMissingAzpRejectedTest = init.then(verifyIdTokenAs(1, true, false, true)).then(all { assert(not(h.idTokenVerified)), assert(safety), h' = h })
  run jwksCooldownEnforcedTest = init.then(refreshJwks).then(refreshJwks).then(all { assert(h.jwksRefreshes == 1), assert(safety), h' = h })
  run subSubstitutionCountermodelTest = init.then(verifyIdTokenAs(1, false, false, true)).then(fetchUserInfoNoSubCheck(2)).then(checkUnsafe)
}
