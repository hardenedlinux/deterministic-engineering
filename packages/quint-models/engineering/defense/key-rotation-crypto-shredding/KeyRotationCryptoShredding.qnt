// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.key-rotation-crypto-shredding
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel require-active-write-epoch step=stepStaleWrite max-steps=6 itf="h.staleWriteViolations > 0"
// @countermodel require-not-shredded step=stepShreddedUse max-steps=6 itf="h.shredReadViolations > 0"
// @countermodel require-digest-preserved step=stepMutatedRewrap max-steps=6 itf="h.rewrapMutationViolations > 0"
// Limits: Bounded 2-epoch rotation and erasure abstraction; arbitrary epoch numbers, tenant AAD isolation, and Merkle root preservation are proved unboundedly in KeyRotationAndCryptoShredding.lean.
module key_rotation_crypto_shredding {
  type State = { activeEpoch: int, writeEpoch: int, epoch1Shredded: bool, digestPreserved: bool, safeOps: int, staleWriteViolations: int, shredReadViolations: int, rewrapMutationViolations: int }
  var h: State
  action init = h' = { activeEpoch: 1, writeEpoch: 1, epoch1Shredded: false, digestPreserved: false, safeOps: 0, staleWriteViolations: 0, shredReadViolations: 0, rewrapMutationViolations: 0 }
  action rotateToEpoch2 = if (h.activeEpoch == 1) h' = h.with("activeEpoch", 2) else h' = h
  action selectEpoch2Write = if ((h.activeEpoch == 2 and h.writeEpoch == 1)) h' = h.with("writeEpoch", 2) else h' = h
  action shredEpoch1Key = if (not(h.epoch1Shredded)) h' = h.with("epoch1Shredded", true) else h' = h
  action verifyPlaintextDigest = if (not(h.digestPreserved)) h' = h.with("digestPreserved", true) else h' = h
  action commitCryptoOp = if ((h.safeOps < 2 and h.writeEpoch == h.activeEpoch and not((h.writeEpoch == 1 and h.epoch1Shredded)) and h.digestPreserved)) h' = h.with("safeOps", (h.safeOps + 1)).with("staleWriteViolations", if (h.writeEpoch == h.activeEpoch) h.staleWriteViolations else (h.staleWriteViolations + 1)).with("shredReadViolations", if (not((h.writeEpoch == 1 and h.epoch1Shredded))) h.shredReadViolations else (h.shredReadViolations + 1)).with("rewrapMutationViolations", if (h.digestPreserved) h.rewrapMutationViolations else (h.rewrapMutationViolations + 1)) else h' = h
  action step = any { rotateToEpoch2, selectEpoch2Write, shredEpoch1Key, verifyPlaintextDigest, commitCryptoOp }
  val safety = (h.staleWriteViolations == 0 and h.shredReadViolations == 0 and h.rewrapMutationViolations == 0)
  // Countermodel engineering.defense.key-rotation-crypto-shredding.stale-write (dropped guard: require-active-write-epoch)
  action commitOpStaleWrite = if ((h.safeOps < 2 and true and not((h.writeEpoch == 1 and h.epoch1Shredded)) and h.digestPreserved)) h' = h.with("safeOps", (h.safeOps + 1)).with("staleWriteViolations", if (h.writeEpoch == h.activeEpoch) h.staleWriteViolations else (h.staleWriteViolations + 1)).with("shredReadViolations", if (not((h.writeEpoch == 1 and h.epoch1Shredded))) h.shredReadViolations else (h.shredReadViolations + 1)).with("rewrapMutationViolations", if (h.digestPreserved) h.rewrapMutationViolations else (h.rewrapMutationViolations + 1)) else h' = h
  action stepStaleWrite = any { step, commitOpStaleWrite }
  // Countermodel engineering.defense.key-rotation-crypto-shredding.shredded-use (dropped guard: require-not-shredded)
  action commitOpShredded = if ((h.safeOps < 2 and h.writeEpoch == h.activeEpoch and true and h.digestPreserved)) h' = h.with("safeOps", (h.safeOps + 1)).with("staleWriteViolations", if (h.writeEpoch == h.activeEpoch) h.staleWriteViolations else (h.staleWriteViolations + 1)).with("shredReadViolations", if (not((h.writeEpoch == 1 and h.epoch1Shredded))) h.shredReadViolations else (h.shredReadViolations + 1)).with("rewrapMutationViolations", if (h.digestPreserved) h.rewrapMutationViolations else (h.rewrapMutationViolations + 1)) else h' = h
  action stepShreddedUse = any { step, commitOpShredded }
  // Countermodel engineering.defense.key-rotation-crypto-shredding.mutated-rewrap (dropped guard: require-digest-preserved)
  action commitOpMutated = if ((h.safeOps < 2 and h.writeEpoch == h.activeEpoch and not((h.writeEpoch == 1 and h.epoch1Shredded)) and true)) h' = h.with("safeOps", (h.safeOps + 1)).with("staleWriteViolations", if (h.writeEpoch == h.activeEpoch) h.staleWriteViolations else (h.staleWriteViolations + 1)).with("shredReadViolations", if (not((h.writeEpoch == 1 and h.epoch1Shredded))) h.shredReadViolations else (h.shredReadViolations + 1)).with("rewrapMutationViolations", if (h.digestPreserved) h.rewrapMutationViolations else (h.rewrapMutationViolations + 1)) else h' = h
  action stepMutatedRewrap = any { step, commitOpMutated }
  run cleanKeyRotationTest = init.then(rotateToEpoch2).then(selectEpoch2Write).then(shredEpoch1Key).then(verifyPlaintextDigest).then(commitCryptoOp).then(all { assert(safety), assert(h.safeOps == 1), h' = h })
  run staleWriteViolatesSafetyTest = init.then(rotateToEpoch2).then(verifyPlaintextDigest).then(commitOpStaleWrite).then(all { assert(not(safety)), assert(h.staleWriteViolations > 0), h' = h })
  run shreddedKeyViolatesSafetyTest = init.then(shredEpoch1Key).then(verifyPlaintextDigest).then(commitOpShredded).then(all { assert(not(safety)), assert(h.shredReadViolations > 0), h' = h })
  run mutatedRewrapViolatesSafetyTest = init.then(commitOpMutated).then(all { assert(not(safety)), assert(h.rewrapMutationViolations > 0), h' = h })
}
