// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.protocol.dpop-sender-constrain
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel cnf-jkt-binding step=stepStolenTokenMisuse max-steps=6 itf="contains(h.acceptedActors, 2)"
// @countermodel jti-replay-cache step=stepDpopProofReplay max-steps=6 itf="h.totalAccepted > size(h.usedJtis)"
// Limits: Finite RFC 9449 / FAPI 2.0 sender-constrain abstraction; does not model asymmetric JWS signature verification mathematics or TLS transport interception.
module dpop_sender_constrain {
  import authority_currentness.* from "../../zero-trust/authority-currentness/AuthorityCurrentness"
  type State = { tokenIssued: bool, tokenBoundKey: int, attackerStoleToken: bool, nextJti: int, usedJtis: Set[int], lastProofJti: int, acceptedActors: Set[int], totalAccepted: int }
  var h: State
  action init = h' = { tokenIssued: false, tokenBoundKey: 1, attackerStoleToken: false, nextJti: 1, usedJtis: Set(), lastProofJti: 0, acceptedActors: Set(), totalAccepted: 0 }
  action issueBoundToken = if (not(h.tokenIssued)) h' = h.with("tokenIssued", true).with("tokenBoundKey", 1) else h' = h
  action stealAccessToken = if ((h.tokenIssued and not(h.attackerStoleToken))) h' = h.with("attackerStoleToken", true) else h' = h
  action rsVerifyAndAccept(actor: int, proofKey: int, jti: int): bool = if ((h.tokenIssued and proofKey == h.tokenBoundKey and not(h.usedJtis.contains(jti)))) h' = h.with("usedJtis", h.usedJtis.union(Set(jti))).with("lastProofJti", jti).with("acceptedActors", h.acceptedActors.union(Set(actor))).with("totalAccepted", (h.totalAccepted + 1)) else h' = h
  action honestSendFresh = if ((h.tokenIssued and h.nextJti <= 3)) h' = h.with("nextJti", (h.nextJti + 1)).with("usedJtis", h.usedJtis.union(Set(h.nextJti))).with("lastProofJti", h.nextJti).with("acceptedActors", h.acceptedActors.union(Set(1))).with("totalAccepted", (h.totalAccepted + 1)) else h' = h
  action attackerTryOwnKey = if ((h.attackerStoleToken and h.nextJti <= 3)) rsVerifyAndAccept(2, 2, h.nextJti) else h' = h
  action attackerReplayProof = if (h.lastProofJti > 0) rsVerifyAndAccept(1, 1, h.lastProofJti) else h' = h
  action step = any { issueBoundToken, stealAccessToken, honestSendFresh, attackerTryOwnKey, attackerReplayProof }
  val safety = (not(h.acceptedActors.contains(2)) and h.totalAccepted == size(h.usedJtis))
  // Countermodel threat.protocol.dpop-sender-constrain.stolen-token-misuse (dropped guard: cnf-jkt-binding)
  action rsVerifyNoCnf(actor: int, proofKey: int, jti: int): bool = if ((h.tokenIssued and true and not(h.usedJtis.contains(jti)))) h' = h.with("usedJtis", h.usedJtis.union(Set(jti))).with("lastProofJti", jti).with("acceptedActors", h.acceptedActors.union(Set(actor))).with("totalAccepted", (h.totalAccepted + 1)) else h' = h
  action stepStolenTokenMisuse = any { step, if ((h.attackerStoleToken and h.nextJti <= 3)) rsVerifyNoCnf(2, 2, h.nextJti) else h' = h }
  // Countermodel threat.protocol.dpop-sender-constrain.dpop-proof-replay (dropped guard: jti-replay-cache)
  action rsVerifyNoJtiCache(actor: int, proofKey: int, jti: int): bool = if ((h.tokenIssued and proofKey == h.tokenBoundKey and true)) h' = h.with("usedJtis", h.usedJtis.union(Set(jti))).with("lastProofJti", jti).with("acceptedActors", h.acceptedActors.union(Set(actor))).with("totalAccepted", (h.totalAccepted + 1)) else h' = h
  action stepDpopProofReplay = any { step, if (h.lastProofJti > 0) rsVerifyNoJtiCache(1, 1, h.lastProofJti) else h' = h }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run stolenTokenBlockedTest = init.then(issueBoundToken).then(stealAccessToken).then(attackerTryOwnKey).then(all { assert(not(h.acceptedActors.contains(2))), assert(safety), h' = h })
  run replayProofBlockedTest = init.then(issueBoundToken).then(honestSendFresh).then(attackerReplayProof).then(all { assert(h.totalAccepted == 1), assert(safety), h' = h })
  run stolenTokenCountermodelTest = init.then(issueBoundToken).then(stealAccessToken).then(rsVerifyNoCnf(2, 2, 1)).then(checkUnsafe)
  run replayCountermodelTest = init.then(issueBoundToken).then(honestSendFresh).then(rsVerifyNoJtiCache(1, 1, 1)).then(checkUnsafe)
}
