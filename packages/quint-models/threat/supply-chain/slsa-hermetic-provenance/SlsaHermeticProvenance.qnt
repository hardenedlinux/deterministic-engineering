// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.supply-chain.slsa-hermetic-provenance
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel slsa-provenance-signed step=stepUnsignedProvenance max-steps=6 itf="h.deployed == true and h.deployedProvenanceSigned == false"
// @countermodel slsa-source-digest-match step=stepUnreviewedSource max-steps=6 itf="h.deployed == true and h.deployedArtifactDigest != h.reviewedSrcDigest"
// @countermodel slsa-reproducible-match step=stepCompromisedBuilderInjection max-steps=6 itf="h.deployed == true and h.deployedArtifactDigest != h.reviewedSrcDigest"
// Limits: Finite two-builder SLSA L3/L4 provenance and reproducible-rebuild abstraction; does not model cryptographic signature forgery, simultaneous collusion of both independent builders, or transitive dependency graph resolution.
module slsa_hermetic_provenance {
  import authority_currentness.* from "../../zero-trust/authority-currentness/AuthorityCurrentness"
  type State = { reviewedSrcDigest: int, b1Built: bool, b1SrcDigest: int, b1ArtifactDigest: int, b1ProvenanceSigned: bool, b2Built: bool, b2SrcDigest: int, b2ArtifactDigest: int, b2ProvenanceSigned: bool, deployed: bool, deployedArtifactDigest: int, deployedProvenanceSigned: bool }
  var h: State
  action init = h' = { reviewedSrcDigest: 1, b1Built: false, b1SrcDigest: 0, b1ArtifactDigest: 0, b1ProvenanceSigned: false, b2Built: false, b2SrcDigest: 0, b2ArtifactDigest: 0, b2ProvenanceSigned: false, deployed: false, deployedArtifactDigest: 0, deployedProvenanceSigned: false }
  action buildB1HonestAs(src: int): bool = if (((src == 1 or src == 2) and not(h.deployed))) h' = h.with("b1Built", true).with("b1SrcDigest", src).with("b1ArtifactDigest", src).with("b1ProvenanceSigned", true) else h' = h
  action buildB1Honest = { nondet src = Set(1, 2).oneOf()
    buildB1HonestAs(src) }
  action buildB1CompromisedTrojan = if (not(h.deployed)) h' = h.with("b1Built", true).with("b1SrcDigest", 1).with("b1ArtifactDigest", 99).with("b1ProvenanceSigned", true) else h' = h
  action forgeUnsignedProvenance = if (not(h.deployed)) h' = h.with("b1Built", true).with("b1SrcDigest", 1).with("b1ArtifactDigest", 1).with("b1ProvenanceSigned", false) else h' = h
  action buildB2IndependentAs(src: int): bool = if (((src == 1 or src == 2) and not(h.deployed))) h' = h.with("b2Built", true).with("b2SrcDigest", src).with("b2ArtifactDigest", src).with("b2ProvenanceSigned", true) else h' = h
  action buildB2Independent = { nondet src = Set(1, 2).oneOf()
    buildB2IndependentAs(src) }
  action admitDeployment = if ((h.b1Built and not(h.deployed) and h.b1ProvenanceSigned and h.b1SrcDigest == h.reviewedSrcDigest and (h.b2Built and h.b2ProvenanceSigned and h.b2SrcDigest == h.b1SrcDigest and h.b1ArtifactDigest == h.b2ArtifactDigest))) h' = h.with("deployed", true).with("deployedArtifactDigest", h.b1ArtifactDigest).with("deployedProvenanceSigned", h.b1ProvenanceSigned) else h' = h
  action step = any { buildB1Honest, buildB1CompromisedTrojan, forgeUnsignedProvenance, buildB2Independent, admitDeployment }
  val safety = (not(h.deployed) or (h.deployedArtifactDigest == h.reviewedSrcDigest and h.deployedProvenanceSigned))
  // Countermodel threat.supply-chain.slsa-hermetic-provenance.unsigned-provenance (dropped guard: slsa-provenance-signed)
  action admitNoSignatureCheck = if ((h.b1Built and not(h.deployed) and true and h.b1SrcDigest == h.reviewedSrcDigest and (h.b2Built and h.b2ProvenanceSigned and h.b2SrcDigest == h.b1SrcDigest and h.b1ArtifactDigest == h.b2ArtifactDigest))) h' = h.with("deployed", true).with("deployedArtifactDigest", h.b1ArtifactDigest).with("deployedProvenanceSigned", h.b1ProvenanceSigned) else h' = h
  action stepUnsignedProvenance = any { step, admitNoSignatureCheck }
  // Countermodel threat.supply-chain.slsa-hermetic-provenance.unreviewed-source (dropped guard: slsa-source-digest-match)
  action admitNoSourceMatch = if ((h.b1Built and not(h.deployed) and h.b1ProvenanceSigned and true and (h.b2Built and h.b2ProvenanceSigned and h.b2SrcDigest == h.b1SrcDigest and h.b1ArtifactDigest == h.b2ArtifactDigest))) h' = h.with("deployed", true).with("deployedArtifactDigest", h.b1ArtifactDigest).with("deployedProvenanceSigned", h.b1ProvenanceSigned) else h' = h
  action stepUnreviewedSource = any { step, admitNoSourceMatch }
  // Countermodel threat.supply-chain.slsa-hermetic-provenance.compromised-builder-injection (dropped guard: slsa-reproducible-match)
  action admitNoReproducibleCheck = if ((h.b1Built and not(h.deployed) and h.b1ProvenanceSigned and h.b1SrcDigest == h.reviewedSrcDigest and true)) h' = h.with("deployed", true).with("deployedArtifactDigest", h.b1ArtifactDigest).with("deployedProvenanceSigned", h.b1ProvenanceSigned) else h' = h
  action stepCompromisedBuilderInjection = any { step, admitNoReproducibleCheck }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run validReproducibleDeployTest = init.then(buildB1HonestAs(1)).then(buildB2IndependentAs(1)).then(admitDeployment).then(all { assert(h.deployed), assert(h.deployedArtifactDigest == 1), assert(h.deployedProvenanceSigned), assert(safety), h' = h })
  run compromisedBuilderTrojanBlockedTest = init.then(buildB1CompromisedTrojan).then(buildB2IndependentAs(1)).then(admitDeployment).then(all { assert(not(h.deployed)), assert(safety), h' = h })
  run unsignedProvenanceCountermodelTest = init.then(forgeUnsignedProvenance).then(buildB2IndependentAs(1)).then(admitNoSignatureCheck).then(checkUnsafe)
  run unreviewedSourceCountermodelTest = init.then(buildB1HonestAs(2)).then(buildB2IndependentAs(2)).then(admitNoSourceMatch).then(checkUnsafe)
  run compromisedBuilderCountermodelTest = init.then(buildB1CompromisedTrojan).then(admitNoReproducibleCheck).then(checkUnsafe)
}
