// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.witness-quorum-finality
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel require-consistency-before-cosign step=stepUnverifiedCosign max-steps=6 itf="h.unverifiedCosignViolations > 0"
// @countermodel forbid-honest-double-sign step=stepHonestEquivocation max-steps=6 itf="h.honestEquivocationViolations > 0"
// @countermodel enforce-quorum-2f1 step=stepSubQuorum max-steps=6 itf="h.subQuorumViolations > 0"
// Limits: Finite N=4 (f=1, t=3) Byzantine witness cosigning quorum-intersection abstraction; assumes static witness roster and <= f compromised witnesses (safety breaks if > f witnesses collude).
module witness_quorum_finality {
  type State = { w1Branch: int, w2Branch: int, w3Branch: int, byzClean: bool, byzBackdoor: bool, consistencyOk: bool, cleanVotes: int, backdoorVotes: int, cleanFinalized: bool, backdoorFinalized: bool, unverifiedCosignViolations: int, honestEquivocationViolations: int, subQuorumViolations: int }
  var h: State
  action init = h' = { w1Branch: 0, w2Branch: 0, w3Branch: 0, byzClean: false, byzBackdoor: false, consistencyOk: false, cleanVotes: 0, backdoorVotes: 0, cleanFinalized: false, backdoorFinalized: false, unverifiedCosignViolations: 0, honestEquivocationViolations: 0, subQuorumViolations: 0 }
  action verifyConsistencyProof = if (not(h.consistencyOk)) h' = h.with("consistencyOk", true) else h' = h
  action w1CosignClean = if ((h.w1Branch != 1 and h.consistencyOk and h.w1Branch == 0)) h' = h.with("w1Branch", 1).with("cleanVotes", (h.cleanVotes + 1)).with("unverifiedCosignViolations", if (h.consistencyOk) h.unverifiedCosignViolations else (h.unverifiedCosignViolations + 1)).with("honestEquivocationViolations", if (h.w1Branch == 0) h.honestEquivocationViolations else (h.honestEquivocationViolations + 1)) else h' = h
  action w1CosignBackdoor = if ((h.consistencyOk and h.w1Branch == 0)) h' = h.with("w1Branch", 2).with("backdoorVotes", (h.backdoorVotes + 1)) else h' = h
  action w2CosignClean = if (h.w2Branch == 0) h' = h.with("w2Branch", 1).with("cleanVotes", (h.cleanVotes + 1)) else h' = h
  action w3CosignBackdoor = if (h.w3Branch == 0) h' = h.with("w3Branch", 2).with("backdoorVotes", (h.backdoorVotes + 1)) else h' = h
  action byzW4DoubleSignBoth = if ((not(h.byzClean) or not(h.byzBackdoor))) h' = h.with("byzClean", true).with("byzBackdoor", true).with("cleanVotes", if (h.byzClean) h.cleanVotes else (h.cleanVotes + 1)).with("backdoorVotes", if (h.byzBackdoor) h.backdoorVotes else (h.backdoorVotes + 1)) else h' = h
  action finalizeClean = if ((not(h.cleanFinalized) and h.cleanVotes >= 3)) h' = h.with("cleanFinalized", true).with("subQuorumViolations", if (h.cleanVotes >= 3) h.subQuorumViolations else (h.subQuorumViolations + 1)) else h' = h
  action finalizeBackdoor = if ((not(h.backdoorFinalized) and h.backdoorVotes >= 3)) h' = h.with("backdoorFinalized", true) else h' = h
  action step = any { verifyConsistencyProof, w1CosignClean, w1CosignBackdoor, w2CosignClean, w3CosignBackdoor, byzW4DoubleSignBoth, finalizeClean, finalizeBackdoor }
  val safety = (not((h.cleanFinalized and h.backdoorFinalized)) and h.unverifiedCosignViolations == 0 and h.honestEquivocationViolations == 0 and h.subQuorumViolations == 0)
  // Countermodel engineering.defense.witness-quorum-finality.unverified-cosign (dropped guard: require-consistency-before-cosign)
  action w1CosignUnverified = if ((h.w1Branch != 1 and true and h.w1Branch == 0)) h' = h.with("w1Branch", 1).with("cleanVotes", (h.cleanVotes + 1)).with("unverifiedCosignViolations", if (h.consistencyOk) h.unverifiedCosignViolations else (h.unverifiedCosignViolations + 1)).with("honestEquivocationViolations", if (h.w1Branch == 0) h.honestEquivocationViolations else (h.honestEquivocationViolations + 1)) else h' = h
  action stepUnverifiedCosign = any { step, w1CosignUnverified }
  // Countermodel engineering.defense.witness-quorum-finality.honest-equivocation (dropped guard: forbid-honest-double-sign)
  action w1DoubleSignClean = if ((h.w1Branch != 1 and h.consistencyOk and true)) h' = h.with("w1Branch", 1).with("cleanVotes", (h.cleanVotes + 1)).with("unverifiedCosignViolations", if (h.consistencyOk) h.unverifiedCosignViolations else (h.unverifiedCosignViolations + 1)).with("honestEquivocationViolations", if (h.w1Branch == 0) h.honestEquivocationViolations else (h.honestEquivocationViolations + 1)) else h' = h
  action stepHonestEquivocation = any { step, w1DoubleSignClean }
  // Countermodel engineering.defense.witness-quorum-finality.sub-quorum (dropped guard: enforce-quorum-2f1)
  action finalizeCleanSubQuorum = if ((not(h.cleanFinalized) and true)) h' = h.with("cleanFinalized", true).with("subQuorumViolations", if (h.cleanVotes >= 3) h.subQuorumViolations else (h.subQuorumViolations + 1)) else h' = h
  action stepSubQuorum = any { step, finalizeCleanSubQuorum }
  run quorumIntersectionPreventsConflictingFinalityTest = init.then(verifyConsistencyProof).then(w1CosignClean).then(w2CosignClean).then(byzW4DoubleSignBoth).then(w3CosignBackdoor).then(finalizeClean).then(finalizeBackdoor).then(all { assert(safety), assert(h.cleanFinalized), assert(not(h.backdoorFinalized)), h' = h })
  run unverifiedCosignViolatesSafetyTest = init.then(w1CosignUnverified).then(all { assert(not(safety)), assert(h.unverifiedCosignViolations > 0), h' = h })
  run honestEquivocationViolatesSafetyTest = init.then(verifyConsistencyProof).then(w1CosignBackdoor).then(w1DoubleSignClean).then(all { assert(not(safety)), assert(h.honestEquivocationViolations > 0), h' = h })
  run subQuorumViolatesSafetyTest = init.then(finalizeCleanSubQuorum).then(all { assert(not(safety)), assert(h.subQuorumViolations > 0), h' = h })
}
