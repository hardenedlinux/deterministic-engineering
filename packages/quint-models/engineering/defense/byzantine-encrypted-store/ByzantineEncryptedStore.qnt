// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.byzantine-encrypted-store
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel require-partition-aead-key step=stepPlaintextLeak max-steps=6 itf="h.oracleLeaks > 0"
// @countermodel require-aead-tag-and-aad step=stepCiphertextForgery max-steps=6 itf="h.forgedVerdicts > 0"
// @countermodel require-m2-memo-freshness step=stepDriftedReplay max-steps=6 itf="h.driftedReplays > 0"
// Limits: Finite single-partition Byzantine AEAD confidentiality/integrity and single-step M2 semantic-drift abstraction; does not model side-channel timing attacks, compromised KMS root keys, or multi-step prompt-injection covert channels.
module byzantine_encrypted_store {
  type State = { coderCompromised: bool, goldEncrypted: bool, ciphertextTampered: bool, aeadVerified: bool, upstreamDrifted: bool, memoRevalidated: bool, oracleLeaks: int, forgedVerdicts: int, driftedReplays: int }
  var h: State
  action init = h' = { coderCompromised: false, goldEncrypted: true, ciphertextTampered: false, aeadVerified: true, upstreamDrifted: false, memoRevalidated: true, oracleLeaks: 0, forgedVerdicts: 0, driftedReplays: 0 }
  action injectPromptIntoCoder = if (not(h.coderCompromised)) h' = h.with("coderCompromised", true) else h' = h
  action tamperOrTransplantRow = if ((h.coderCompromised and not(h.ciphertextTampered))) h' = h.with("ciphertextTampered", true).with("aeadVerified", false) else h' = h
  action restoreAuthenticCiphertext = if (h.ciphertextTampered) h' = h.with("ciphertextTampered", false).with("aeadVerified", true) else h' = h
  action driftUpstreamManifest = if (not(h.upstreamDrifted)) h' = h.with("upstreamDrifted", true).with("memoRevalidated", false) else h' = h
  action repromptDriftedStep = if ((h.upstreamDrifted and not(h.memoRevalidated))) h' = h.with("memoRevalidated", true) else h' = h
  action readReviewerGold = if (not(h.coderCompromised)) h' = h.with("oracleLeaks", if (h.coderCompromised) (h.oracleLeaks + 1) else h.oracleLeaks) else h' = h
  action acceptEncryptedVerdict = if ((h.aeadVerified and not(h.ciphertextTampered))) h' = h.with("forgedVerdicts", if ((h.ciphertextTampered or not(h.aeadVerified))) (h.forgedVerdicts + 1) else h.forgedVerdicts) else h' = h
  action replayMemoizedLlmStep = if ((not(h.upstreamDrifted) or h.memoRevalidated)) h' = h.with("driftedReplays", if ((h.upstreamDrifted and not(h.memoRevalidated))) (h.driftedReplays + 1) else h.driftedReplays) else h' = h
  action step = any { injectPromptIntoCoder, tamperOrTransplantRow, restoreAuthenticCiphertext, driftUpstreamManifest, repromptDriftedStep, readReviewerGold, acceptEncryptedVerdict, replayMemoizedLlmStep }
  val safety = (h.goldEncrypted and h.oracleLeaks == 0 and h.forgedVerdicts == 0 and h.driftedReplays == 0)
  // Countermodel engineering.defense.byzantine-encrypted-store.plaintext-leak (dropped guard: require-partition-aead-key)
  action readReviewerGoldNoKeyCheck = if (true) h' = h.with("oracleLeaks", if (h.coderCompromised) (h.oracleLeaks + 1) else h.oracleLeaks) else h' = h
  action stepPlaintextLeak = any { step, readReviewerGoldNoKeyCheck }
  // Countermodel engineering.defense.byzantine-encrypted-store.ciphertext-forgery (dropped guard: require-aead-tag-and-aad)
  action acceptUnverifiedCiphertext = if (true) h' = h.with("forgedVerdicts", if ((h.ciphertextTampered or not(h.aeadVerified))) (h.forgedVerdicts + 1) else h.forgedVerdicts) else h' = h
  action stepCiphertextForgery = any { step, acceptUnverifiedCiphertext }
  // Countermodel engineering.defense.byzantine-encrypted-store.drifted-replay (dropped guard: require-m2-memo-freshness)
  action replayDriftedMemoBlindly = if (true) h' = h.with("driftedReplays", if ((h.upstreamDrifted and not(h.memoRevalidated))) (h.driftedReplays + 1) else h.driftedReplays) else h' = h
  action stepDriftedReplay = any { step, replayDriftedMemoBlindly }
  run encryptedIsolationAndDriftRevalidateSafeTest = init.then(injectPromptIntoCoder).then(tamperOrTransplantRow).then(acceptEncryptedVerdict).then(readReviewerGold).then(restoreAuthenticCiphertext).then(acceptEncryptedVerdict).then(driftUpstreamManifest).then(repromptDriftedStep).then(replayMemoizedLlmStep).then(all { assert(safety), assert(h.coderCompromised), assert(h.memoRevalidated), h' = h })
  run plaintextLeakViolatesSafetyTest = init.then(injectPromptIntoCoder).then(readReviewerGoldNoKeyCheck).then(all { assert(not(safety)), assert(h.oracleLeaks > 0), h' = h })
  run ciphertextForgeryViolatesSafetyTest = init.then(injectPromptIntoCoder).then(tamperOrTransplantRow).then(acceptUnverifiedCiphertext).then(all { assert(not(safety)), assert(h.forgedVerdicts > 0), h' = h })
  run driftedReplayViolatesSafetyTest = init.then(driftUpstreamManifest).then(replayDriftedMemoBlindly).then(all { assert(not(safety)), assert(h.driftedReplays > 0), h' = h })
}
