// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.protocol.mls-ratchet-pcs
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel ratchet-zeroize-old-key step=stepRetainOldKey max-steps=6 itf="h.pastMsgDecrypted == true and h.pastKeyRetained == true"
// @countermodel ratchet-fresh-entropy step=stepNoFreshEntropyPcs max-steps=6 itf="h.postHealMsgDecrypted == true and h.healed == true"
// @countermodel commit-rotate-on-remove step=stepRemoveWithoutRotate max-steps=6 itf="h.removedMemberDecrypted == true and h.bobRemoved == true"
// Limits: Symbolic Dolev-Yao abstraction of MLS (RFC 9420) / Double Ratchet epoch key evolution, zeroization, fresh-entropy healing, and removal rotation; does not model TreeKEM blank-node path compression, active delivery-service fork attacks, or IND-CCA KEM assumptions.
module mls_ratchet_pcs {
  type State = { epoch: int, keyGen: int, pastMsgSent: bool, pastMsgKeyGen: int, pastKeyRetained: bool, compromised: bool, attackerKeyGen: int, healed: bool, postHealMsgSent: bool, postHealMsgKeyGen: int, bobRemoved: bool, bobKeyGen: int, postRemoveMsgSent: bool, postRemoveMsgKeyGen: int, pastMsgDecrypted: bool, postHealMsgDecrypted: bool, removedMemberDecrypted: bool }
  var h: State
  action init = h' = { epoch: 1, keyGen: 1, pastMsgSent: false, pastMsgKeyGen: 0, pastKeyRetained: false, compromised: false, attackerKeyGen: 0, healed: false, postHealMsgSent: false, postHealMsgKeyGen: 0, bobRemoved: false, bobKeyGen: 1, postRemoveMsgSent: false, postRemoveMsgKeyGen: 0, pastMsgDecrypted: false, postHealMsgDecrypted: false, removedMemberDecrypted: false }
  action sendPastMessage = if ((h.epoch == 1 and not(h.pastMsgSent))) h' = h.with("pastMsgSent", true).with("pastMsgKeyGen", h.keyGen) else h' = h
  action advanceEpochRegular = if ((h.epoch < 5 and h.pastMsgSent and not(h.compromised))) h' = h.with("epoch", (h.epoch + 1)).with("keyGen", (h.keyGen + 1)).with("bobKeyGen", if (h.bobRemoved) h.bobKeyGen else (h.keyGen + 1)).with("pastKeyRetained", false) else h' = h
  action compromiseCurrentState = if ((h.epoch >= 2 and not(h.compromised))) h' = h.with("compromised", true).with("attackerKeyGen", h.keyGen) else h' = h
  action ratchetHealPcs = if ((h.compromised and not(h.healed) and h.epoch < 5)) h' = h.with("epoch", (h.epoch + 1)).with("healed", true).with("keyGen", (h.keyGen + 1)).with("bobKeyGen", if (h.bobRemoved) h.bobKeyGen else (h.keyGen + 1)) else h' = h
  action sendPostHealMessage = if ((h.healed and not(h.postHealMsgSent))) h' = h.with("postHealMsgSent", true).with("postHealMsgKeyGen", h.keyGen) else h' = h
  action removeBobCommit = if ((not(h.bobRemoved) and h.epoch < 5)) h' = h.with("epoch", (h.epoch + 1)).with("bobRemoved", true).with("keyGen", (h.keyGen + 1)) else h' = h
  action sendPostRemoveMessage = if ((h.bobRemoved and not(h.postRemoveMsgSent))) h' = h.with("postRemoveMsgSent", true).with("postRemoveMsgKeyGen", h.keyGen) else h' = h
  action attackerDecryptPast = if ((h.compromised and h.pastMsgSent and (h.attackerKeyGen == h.pastMsgKeyGen or h.pastKeyRetained))) h' = h.with("pastMsgDecrypted", true) else h' = h
  action attackerDecryptPostHeal = if ((h.compromised and h.postHealMsgSent and h.attackerKeyGen == h.postHealMsgKeyGen)) h' = h.with("postHealMsgDecrypted", true) else h' = h
  action bobDecryptPostRemove = if ((h.bobRemoved and h.postRemoveMsgSent and h.bobKeyGen == h.postRemoveMsgKeyGen)) h' = h.with("removedMemberDecrypted", true) else h' = h
  action step = any { sendPastMessage, advanceEpochRegular, compromiseCurrentState, ratchetHealPcs, sendPostHealMessage, removeBobCommit, sendPostRemoveMessage, attackerDecryptPast, attackerDecryptPostHeal, bobDecryptPostRemove }
  val safety = (not(h.pastMsgDecrypted) and not(h.postHealMsgDecrypted) and not(h.removedMemberDecrypted))
  // Countermodel threat.protocol.mls-ratchet-pcs.retain-old-key (dropped guard: ratchet-zeroize-old-key)
  action advanceEpochRetainOldKey = if ((h.epoch < 5 and h.pastMsgSent and not(h.compromised))) h' = h.with("epoch", (h.epoch + 1)).with("keyGen", (h.keyGen + 1)).with("bobKeyGen", if (h.bobRemoved) h.bobKeyGen else (h.keyGen + 1)).with("pastKeyRetained", true) else h' = h
  action stepRetainOldKey = any { step, advanceEpochRetainOldKey }
  // Countermodel threat.protocol.mls-ratchet-pcs.no-fresh-entropy-pcs (dropped guard: ratchet-fresh-entropy)
  action ratchetHealNoEntropy = if ((h.compromised and not(h.healed) and h.epoch < 5)) h' = h.with("epoch", (h.epoch + 1)).with("healed", true).with("keyGen", h.keyGen).with("bobKeyGen", if (h.bobRemoved) h.bobKeyGen else h.keyGen) else h' = h
  action stepNoFreshEntropyPcs = any { step, ratchetHealNoEntropy }
  // Countermodel threat.protocol.mls-ratchet-pcs.remove-without-rotate (dropped guard: commit-rotate-on-remove)
  action removeBobNoRotate = if ((not(h.bobRemoved) and h.epoch < 5)) h' = h.with("epoch", (h.epoch + 1)).with("bobRemoved", true).with("keyGen", h.keyGen) else h' = h
  action stepRemoveWithoutRotate = any { step, removeBobNoRotate }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run fullFsPcsAndRemovalLifecycleTest = init.then(sendPastMessage).then(advanceEpochRegular).then(compromiseCurrentState).then(attackerDecryptPast).then(ratchetHealPcs).then(sendPostHealMessage).then(attackerDecryptPostHeal).then(removeBobCommit).then(sendPostRemoveMessage).then(bobDecryptPostRemove).then(all { assert(h.pastMsgSent), assert(h.postHealMsgSent), assert(h.postRemoveMsgSent), assert(safety), h' = h })
  run retainOldKeyBreaksFsCountermodelTest = init.then(sendPastMessage).then(advanceEpochRetainOldKey).then(compromiseCurrentState).then(attackerDecryptPast).then(checkUnsafe)
  run noFreshEntropyBreaksPcsCountermodelTest = init.then(sendPastMessage).then(advanceEpochRegular).then(compromiseCurrentState).then(ratchetHealNoEntropy).then(sendPostHealMessage).then(attackerDecryptPostHeal).then(checkUnsafe)
  run removeWithoutRotateCountermodelTest = init.then(removeBobNoRotate).then(sendPostRemoveMessage).then(bobDecryptPostRemove).then(checkUnsafe)
}
