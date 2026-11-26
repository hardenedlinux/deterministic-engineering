// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.protocol.tls13-0rtt-forward-secrecy
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel reject-non-idempotent-0rtt step=stepNonIdempotentZeroRtt max-steps=6 itf="h.nonIdempotentZeroRttExecutions > 0"
// @countermodel cross-edge-strike-sync step=stepCrossEdgeReplay max-steps=6 itf="h.zeroRttExecutions > h.clientSentZeroRtt"
// @countermodel require-ecdhe-pfs step=stepPskOnlyNoPfs max-steps=6 itf="h.secretRecovered == true and h.pskCompromised == true and h.capturedNonPfsSecret == true"
// Limits: Symbolic Dolev-Yao abstraction of TLS 1.3 / Noise 0-RTT anti-replay across 2 edge nodes and post-compromise forward secrecy; does not model cryptographic key schedule collision bounds, ticket age skew windows, or active MitM downgrade cipher suites.
module tls13_0rtt_forward_secrecy {
  type State = { pskIssued: bool, pskCompromised: bool, ecdheDone: bool, clientSentZeroRtt: int, zeroRttNonIdempotent: bool, capturedZeroRtt: bool, capturedNonPfsSecret: bool, capturedPfsSecret: bool, nodeAStrikeUsed: bool, nodeBStrikeUsed: bool, zeroRttExecutions: int, nonIdempotentZeroRttExecutions: int, secretRecovered: bool }
  var h: State
  action init = h' = { pskIssued: false, pskCompromised: false, ecdheDone: false, clientSentZeroRtt: 0, zeroRttNonIdempotent: false, capturedZeroRtt: false, capturedNonPfsSecret: false, capturedPfsSecret: false, nodeAStrikeUsed: false, nodeBStrikeUsed: false, zeroRttExecutions: 0, nonIdempotentZeroRttExecutions: 0, secretRecovered: false }
  action issueResumptionPsk = if (not(h.pskIssued)) h' = h.with("pskIssued", true) else h' = h
  action clientSendZeroRttAs(isNonIdempotent: bool): bool = if ((h.pskIssued and h.clientSentZeroRtt == 0)) h' = h.with("clientSentZeroRtt", 1).with("zeroRttNonIdempotent", isNonIdempotent).with("capturedZeroRtt", true) else h' = h
  action clientSendZeroRtt = { nondet isNonIdempotent = Set(true, false).oneOf()
    clientSendZeroRttAs(isNonIdempotent) }
  action edgeProcessZeroRttAs(node: int): bool = if ((h.capturedZeroRtt and not(h.zeroRttNonIdempotent) and (if (node == 1) (not(h.nodeAStrikeUsed) and not(h.nodeBStrikeUsed)) else (not(h.nodeBStrikeUsed) and not(h.nodeAStrikeUsed))))) h' = h.with("nodeAStrikeUsed", if (node == 1) true else h.nodeAStrikeUsed).with("nodeBStrikeUsed", if (node == 2) true else h.nodeBStrikeUsed).with("zeroRttExecutions", (h.zeroRttExecutions + 1)).with("nonIdempotentZeroRttExecutions", if (h.zeroRttNonIdempotent) (h.nonIdempotentZeroRttExecutions + 1) else h.nonIdempotentZeroRttExecutions) else h' = h
  action edgeProcessZeroRtt = { nondet node = Set(1, 2).oneOf()
    edgeProcessZeroRttAs(node) }
  action completeEcdheHandshake = if ((h.pskIssued and not(h.ecdheDone))) h' = h.with("ecdheDone", true) else h' = h
  action clientSendConfidentialSecret = if ((h.pskIssued and not(h.capturedPfsSecret) and not(h.capturedNonPfsSecret) and h.ecdheDone)) if (h.ecdheDone) h' = h.with("capturedPfsSecret", true) else h' = h.with("capturedNonPfsSecret", true) else h' = h
  action compromiseLongTermPsk = if ((h.pskIssued and not(h.pskCompromised))) h' = h.with("pskCompromised", true) else h' = h
  action attackerDecryptTranscript = if ((h.pskCompromised and h.capturedNonPfsSecret)) h' = h.with("secretRecovered", true) else h' = h
  action step = any { issueResumptionPsk, clientSendZeroRtt, edgeProcessZeroRtt, completeEcdheHandshake, clientSendConfidentialSecret, compromiseLongTermPsk, attackerDecryptTranscript }
  val safety = (h.nonIdempotentZeroRttExecutions == 0 and h.zeroRttExecutions <= h.clientSentZeroRtt and not(h.secretRecovered))
  // Countermodel threat.protocol.tls13-0rtt-forward-secrecy.non-idempotent-0rtt (dropped guard: reject-non-idempotent-0rtt)
  action edgeProcessNonIdempotent(node: int): bool = if ((h.capturedZeroRtt and true and (if (node == 1) (not(h.nodeAStrikeUsed) and not(h.nodeBStrikeUsed)) else (not(h.nodeBStrikeUsed) and not(h.nodeAStrikeUsed))))) h' = h.with("nodeAStrikeUsed", if (node == 1) true else h.nodeAStrikeUsed).with("nodeBStrikeUsed", if (node == 2) true else h.nodeBStrikeUsed).with("zeroRttExecutions", (h.zeroRttExecutions + 1)).with("nonIdempotentZeroRttExecutions", if (h.zeroRttNonIdempotent) (h.nonIdempotentZeroRttExecutions + 1) else h.nonIdempotentZeroRttExecutions) else h' = h
  action stepNonIdempotentZeroRtt = any { step, { nondet node = Set(1, 2).oneOf()
    edgeProcessNonIdempotent(node) } }
  // Countermodel threat.protocol.tls13-0rtt-forward-secrecy.cross-edge-replay (dropped guard: cross-edge-strike-sync)
  action edgeProcessUnsyncedStrike(node: int): bool = if ((h.capturedZeroRtt and not(h.zeroRttNonIdempotent) and (if (node == 1) (not(h.nodeAStrikeUsed) and true) else (not(h.nodeBStrikeUsed) and true)))) h' = h.with("nodeAStrikeUsed", if (node == 1) true else h.nodeAStrikeUsed).with("nodeBStrikeUsed", if (node == 2) true else h.nodeBStrikeUsed).with("zeroRttExecutions", (h.zeroRttExecutions + 1)).with("nonIdempotentZeroRttExecutions", if (h.zeroRttNonIdempotent) (h.nonIdempotentZeroRttExecutions + 1) else h.nonIdempotentZeroRttExecutions) else h' = h
  action stepCrossEdgeReplay = any { step, { nondet node = Set(1, 2).oneOf()
    edgeProcessUnsyncedStrike(node) } }
  // Countermodel threat.protocol.tls13-0rtt-forward-secrecy.psk-only-no-pfs (dropped guard: require-ecdhe-pfs)
  action clientSendSecretNoPfs = if ((h.pskIssued and not(h.capturedPfsSecret) and not(h.capturedNonPfsSecret) and true)) if (h.ecdheDone) h' = h.with("capturedPfsSecret", true) else h' = h.with("capturedNonPfsSecret", true) else h' = h
  action stepPskOnlyNoPfs = any { step, clientSendSecretNoPfs }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run pfsSurvivesPostCompromiseTest = init.then(issueResumptionPsk).then(clientSendZeroRttAs(false)).then(edgeProcessZeroRttAs(1)).then(edgeProcessZeroRttAs(2)).then(completeEcdheHandshake).then(clientSendConfidentialSecret).then(compromiseLongTermPsk).then(attackerDecryptTranscript).then(all { assert(h.zeroRttExecutions == 1), assert(h.capturedPfsSecret), assert(not(h.secretRecovered)), assert(safety), h' = h })
  run nonIdempotentZeroRttCountermodelTest = init.then(issueResumptionPsk).then(clientSendZeroRttAs(true)).then(edgeProcessNonIdempotent(1)).then(checkUnsafe)
  run crossEdgeReplayCountermodelTest = init.then(issueResumptionPsk).then(clientSendZeroRttAs(false)).then(edgeProcessZeroRttAs(1)).then(edgeProcessUnsyncedStrike(2)).then(checkUnsafe)
  run noForwardSecrecyCountermodelTest = init.then(issueResumptionPsk).then(clientSendSecretNoPfs).then(compromiseLongTermPsk).then(attackerDecryptTranscript).then(checkUnsafe)
}
