// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.identity.webauthn-passkey-ceremony
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel rpid-origin-binding step=stepPhishingOriginRelay max-steps=6 itf="h.totalLogins >= 1 and h.lastAcceptedOrigin != h.rpOrigin"
// @countermodel challenge-single-use step=stepChallengeReplay max-steps=6 itf="h.totalLogins > size(h.consumedChallenges)"
// @countermodel signcount-monotonicity step=stepClonedSignCount max-steps=6 itf="h.totalLogins >= 2 and h.lastAcceptedCounter <= h.prevStoredCounter"
// Limits: Finite WebAuthn/FIDO2 ceremony abstraction; assumes honest browser origin reporting and does not model endpoint malware, COSE signature mathematics, or synced zero-counter passkeys.
module webauthn_passkey_ceremony {
  import authority_currentness.* from "../../zero-trust/authority-currentness/AuthorityCurrentness"
  type State = { rpOrigin: int, activeChallenge: int, nextChallenge: int, consumedChallenges: Set[int], rpStoredCounter: int, prevStoredCounter: int, lastAcceptedOrigin: int, lastAcceptedCounter: int, totalLogins: int }
  var h: State
  action init = h' = { rpOrigin: 1, activeChallenge: 0, nextChallenge: 1, consumedChallenges: Set(), rpStoredCounter: 0, prevStoredCounter: 0, lastAcceptedOrigin: 1, lastAcceptedCounter: 1, totalLogins: 0 }
  action issueChallenge = if ((h.activeChallenge == 0 and h.nextChallenge <= 3)) h' = h.with("activeChallenge", h.nextChallenge).with("nextChallenge", (h.nextChallenge + 1)) else h' = h
  action rpVerifyAssertion(origin: int, ch: int, cnt: int): bool = if ((origin == h.rpOrigin and (ch > 0 and ch == h.activeChallenge and not(h.consumedChallenges.contains(ch))) and cnt > h.rpStoredCounter)) h' = h.with("consumedChallenges", h.consumedChallenges.union(Set(ch))).with("activeChallenge", 0).with("prevStoredCounter", h.rpStoredCounter).with("rpStoredCounter", if (cnt > h.rpStoredCounter) cnt else h.rpStoredCounter).with("lastAcceptedOrigin", origin).with("lastAcceptedCounter", cnt).with("totalLogins", (h.totalLogins + 1)) else h' = h
  action honestSignAndVerify = if (h.activeChallenge > 0) rpVerifyAssertion(1, h.activeChallenge, (h.rpStoredCounter + 1)) else h' = h
  action phishingRelayAttempt = if (h.activeChallenge > 0) rpVerifyAssertion(2, h.activeChallenge, (h.rpStoredCounter + 1)) else h' = h
  action replayOldAssertion = { nondet c = Set(1, 2, 3).oneOf()
    if (h.consumedChallenges.contains(c)) rpVerifyAssertion(1, c, (h.rpStoredCounter + 1)) else h' = h }
  action clonedTokenAttempt = if ((h.activeChallenge > 0 and h.rpStoredCounter > 0)) rpVerifyAssertion(1, h.activeChallenge, h.rpStoredCounter) else h' = h
  action step = any { issueChallenge, honestSignAndVerify, phishingRelayAttempt, replayOldAssertion, clonedTokenAttempt }
  val safety = (h.totalLogins == 0 or (h.lastAcceptedOrigin == h.rpOrigin and h.totalLogins == size(h.consumedChallenges) and h.lastAcceptedCounter > h.prevStoredCounter))
  // Countermodel threat.identity.webauthn-passkey-ceremony.phishing-origin-relay (dropped guard: rpid-origin-binding)
  action rpVerifyNoOrigin(origin: int, ch: int, cnt: int): bool = if ((true and (ch > 0 and ch == h.activeChallenge and not(h.consumedChallenges.contains(ch))) and cnt > h.rpStoredCounter)) h' = h.with("consumedChallenges", h.consumedChallenges.union(Set(ch))).with("activeChallenge", 0).with("prevStoredCounter", h.rpStoredCounter).with("rpStoredCounter", if (cnt > h.rpStoredCounter) cnt else h.rpStoredCounter).with("lastAcceptedOrigin", origin).with("lastAcceptedCounter", cnt).with("totalLogins", (h.totalLogins + 1)) else h' = h
  action stepPhishingOriginRelay = any { step, if (h.activeChallenge > 0) rpVerifyNoOrigin(2, h.activeChallenge, (h.rpStoredCounter + 1)) else h' = h }
  // Countermodel threat.identity.webauthn-passkey-ceremony.challenge-replay (dropped guard: challenge-single-use)
  action rpVerifyNoChallenge(origin: int, ch: int, cnt: int): bool = if ((origin == h.rpOrigin and true and cnt > h.rpStoredCounter)) h' = h.with("consumedChallenges", h.consumedChallenges.union(Set(ch))).with("activeChallenge", 0).with("prevStoredCounter", h.rpStoredCounter).with("rpStoredCounter", if (cnt > h.rpStoredCounter) cnt else h.rpStoredCounter).with("lastAcceptedOrigin", origin).with("lastAcceptedCounter", cnt).with("totalLogins", (h.totalLogins + 1)) else h' = h
  action stepChallengeReplay = any { step, { nondet c = Set(1, 2, 3).oneOf()
    if (h.consumedChallenges.contains(c)) rpVerifyNoChallenge(1, c, (h.rpStoredCounter + 1)) else h' = h } }
  // Countermodel threat.identity.webauthn-passkey-ceremony.cloned-signcount (dropped guard: signcount-monotonicity)
  action rpVerifyNoSignCount(origin: int, ch: int, cnt: int): bool = if ((origin == h.rpOrigin and (ch > 0 and ch == h.activeChallenge and not(h.consumedChallenges.contains(ch))) and true)) h' = h.with("consumedChallenges", h.consumedChallenges.union(Set(ch))).with("activeChallenge", 0).with("prevStoredCounter", h.rpStoredCounter).with("rpStoredCounter", if (cnt > h.rpStoredCounter) cnt else h.rpStoredCounter).with("lastAcceptedOrigin", origin).with("lastAcceptedCounter", cnt).with("totalLogins", (h.totalLogins + 1)) else h' = h
  action stepClonedSignCount = any { step, if ((h.activeChallenge > 0 and h.rpStoredCounter > 0)) rpVerifyNoSignCount(1, h.activeChallenge, h.rpStoredCounter) else h' = h }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run validPasskeyLoginTest = init.then(issueChallenge).then(honestSignAndVerify).then(all { assert(h.totalLogins == 1), assert(h.rpStoredCounter == 1), assert(safety), h' = h })
  run phishingOriginBlockedTest = init.then(issueChallenge).then(phishingRelayAttempt).then(all { assert(h.totalLogins == 0), assert(safety), h' = h })
  run clonedTokenBlockedTest = init.then(issueChallenge).then(honestSignAndVerify).then(issueChallenge).then(clonedTokenAttempt).then(all { assert(h.totalLogins == 1), assert(safety), h' = h })
  run phishingRelayCountermodelTest = init.then(issueChallenge).then(rpVerifyNoOrigin(2, 1, 1)).then(checkUnsafe)
  run challengeReplayCountermodelTest = init.then(issueChallenge).then(honestSignAndVerify).then(rpVerifyNoChallenge(1, 1, 2)).then(checkUnsafe)
  run clonedSignCountCountermodelTest = init.then(issueChallenge).then(honestSignAndVerify).then(issueChallenge).then(rpVerifyNoSignCount(1, 2, 1)).then(checkUnsafe)
}
