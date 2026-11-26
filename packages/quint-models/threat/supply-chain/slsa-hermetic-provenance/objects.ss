;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; SLSA v1.0 Hermetic Build Provenance & Reproducible Multi-Builder Attestation threat model.
;;; Co-located Yuanxu unit: single source of truth alongside SlsaHermeticProvenance.qnt and README.org.
;;; Models non-falsifiable builder-signed provenance (SLSA L3), reviewed source-digest binding,
;;; and independent reproducible rebuild verification (defeating compromised-builder injection).
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export SlsaHermeticProvenanceModel
        SlsaUnsignedProvenanceCountermodel
        SlsaUnreviewedSourceCountermodel
        SlsaCompromisedBuilderInjectionCountermodel)

(.def (SlsaHermeticProvenanceModel @ AuthorityCurrentnessModel)
  identity: 'threat.supply-chain.slsa-hermetic-provenance
  family: 'threat.supply-chain.slsa-hermetic-provenance
  title: "SLSA Hermetic Build Provenance & Reproducible Multi-Builder Attestation"
  subdomain: 'quint.threat.supply-chain
  papers:
  '(("OpenSSF SLSA Specification v1.0 / v1.1 (2023-2025)"
     "Supply-chain Levels for Software Artifacts: non-falsifiable Build L3 provenance and isolated hermetic builds.")
    ("C. Lamb & S. Zacchiroli (IEEE Software 2022)"
     "Reproducible Builds: Increasing the Integrity of Software Supply Chains — independent rebuild verification against compromised builders.")
    ("S. Torres-Arias et al. (USENIX Security 2019)"
     "in-toto: Providing farm-to-table guarantees for bits and bytes."))
  quint-module: "slsa_hermetic_provenance"
  quint-file: "SlsaHermeticProvenance.qnt"
  domain-dir: "threat/supply-chain/slsa-hermetic-provenance"
  quint-imports:
  '(("authority_currentness" "../../zero-trust/authority-currentness/AuthorityCurrentness"))
  rules:
  '((slsa-provenance-signed SLSA-PROV-SIGNED quint)
    (slsa-source-digest-match SLSA-SRC-MATCH quint)
    (slsa-reproducible-match SLSA-REPRO-MATCH quint))
  dependencies:
  '((SLSA-PROV-SIGNED source)
    (SLSA-PROV-SIGNED profile)
    (SLSA-PROV-SIGNED method)
    (SLSA-SRC-MATCH source)
    (SLSA-SRC-MATCH profile)
    (SLSA-SRC-MATCH method)
    (SLSA-REPRO-MATCH source)
    (SLSA-REPRO-MATCH profile)
    (SLSA-REPRO-MATCH method))
  invariant: "Every deployed artifact carries builder-signed provenance and matches the exact reviewed source digest, even if the primary builder is compromised and signs Trojan provenance."
  parameters: '()
  state:
  '((reviewedSrcDigest "int" "1")
    (b1Built "bool" "false")
    (b1SrcDigest "int" "0")
    (b1ArtifactDigest "int" "0")
    (b1ProvenanceSigned "bool" "false")
    (b2Built "bool" "false")
    (b2SrcDigest "int" "0")
    (b2ArtifactDigest "int" "0")
    (b2ProvenanceSigned "bool" "false")
    (deployed "bool" "false")
    (deployedArtifactDigest "int" "0")
    (deployedProvenanceSigned "bool" "false"))
  guards:
  '((slsa-provenance-signed (. h b1ProvenanceSigned))
    (slsa-source-digest-match (= (. h b1SrcDigest) (. h reviewedSrcDigest)))
    (slsa-reproducible-match
      (and (. h b2Built)
           (. h b2ProvenanceSigned)
           (= (. h b2SrcDigest) (. h b1SrcDigest))
           (= (. h b1ArtifactDigest) (. h b2ArtifactDigest)))))
  transitions:
  '((buildB1HonestAs
      (action buildB1HonestAs ((src "int")) "bool"
        (if (and (or (= src 1) (= src 2)) (not (. h deployed)))
          (set-h (b1Built #t)
                 (b1SrcDigest src)
                 (b1ArtifactDigest src)
                 (b1ProvenanceSigned #t))
          (keep-h))))
    (buildB1Honest
      (action buildB1Honest ()
        (nondet ((src (set 1 2)))
          (call buildB1HonestAs src))))
    (buildB1CompromisedTrojan
      (action buildB1CompromisedTrojan ()
        (if (not (. h deployed))
          (set-h (b1Built #t)
                 (b1SrcDigest 1)
                 (b1ArtifactDigest 99)
                 (b1ProvenanceSigned #t))
          (keep-h))))
    (forgeUnsignedProvenance
      (action forgeUnsignedProvenance ()
        (if (not (. h deployed))
          (set-h (b1Built #t)
                 (b1SrcDigest 1)
                 (b1ArtifactDigest 1)
                 (b1ProvenanceSigned #f))
          (keep-h))))
    (buildB2IndependentAs
      (action buildB2IndependentAs ((src "int")) "bool"
        (if (and (or (= src 1) (= src 2)) (not (. h deployed)))
          (set-h (b2Built #t)
                 (b2SrcDigest src)
                 (b2ArtifactDigest src)
                 (b2ProvenanceSigned #t))
          (keep-h))))
    (buildB2Independent
      (action buildB2Independent ()
        (nondet ((src (set 1 2)))
          (call buildB2IndependentAs src))))
    (admitDeployment
      (action admitDeployment ()
        (if (and (. h b1Built)
                 (not (. h deployed))
                 (guard slsa-provenance-signed (. h b1ProvenanceSigned))
                 (guard slsa-source-digest-match (= (. h b1SrcDigest) (. h reviewedSrcDigest)))
                 (guard slsa-reproducible-match
                        (and (. h b2Built)
                             (. h b2ProvenanceSigned)
                             (= (. h b2SrcDigest) (. h b1SrcDigest))
                             (= (. h b1ArtifactDigest) (. h b2ArtifactDigest)))))
          (set-h (deployed #t)
                 (deployedArtifactDigest (. h b1ArtifactDigest))
                 (deployedProvenanceSigned (. h b1ProvenanceSigned)))
          (keep-h))))
    (step
      (action step ()
        (any buildB1Honest buildB1CompromisedTrojan forgeUnsignedProvenance
             buildB2Independent admitDeployment))))
  safety:
  '(or (not (. h deployed))
       (and (= (. h deployedArtifactDigest) (. h reviewedSrcDigest))
            (. h deployedProvenanceSigned)))
  traces:
  '((checkSafe
      (action checkSafe ()
        (all (assert safety) (keep-h))))
    (checkUnsafe
      (action checkUnsafe ()
        (all (assert (not safety)) (keep-h))))
    (validReproducibleDeployTest
      (run validReproducibleDeployTest
        (then init
              (call buildB1HonestAs 1)
              (call buildB2IndependentAs 1)
              admitDeployment
              (all (assert (. h deployed))
                   (assert (= (. h deployedArtifactDigest) 1))
                   (assert (. h deployedProvenanceSigned))
                   (assert safety)
                   (keep-h)))))
    (compromisedBuilderTrojanBlockedTest
      (run compromisedBuilderTrojanBlockedTest
        (then init
              buildB1CompromisedTrojan
              (call buildB2IndependentAs 1)
              admitDeployment
              (all (assert (not (. h deployed)))
                   (assert safety)
                   (keep-h)))))
    (unsignedProvenanceCountermodelTest
      (run unsignedProvenanceCountermodelTest
        (then init
              forgeUnsignedProvenance
              (call buildB2IndependentAs 1)
              admitNoSignatureCheck
              checkUnsafe)))
    (unreviewedSourceCountermodelTest
      (run unreviewedSourceCountermodelTest
        (then init
              (call buildB1HonestAs 2)
              (call buildB2IndependentAs 2)
              admitNoSourceMatch
              checkUnsafe)))
    (compromisedBuilderCountermodelTest
      (run compromisedBuilderCountermodelTest
        (then init
              buildB1CompromisedTrojan
              admitNoReproducibleCheck
              checkUnsafe))))
  countermodels:
  (list SlsaUnsignedProvenanceCountermodel
        SlsaUnreviewedSourceCountermodel
        SlsaCompromisedBuilderInjectionCountermodel)
  limits: "Finite two-builder SLSA L3/L4 provenance and reproducible-rebuild abstraction; does not model cryptographic signature forgery, simultaneous collusion of both independent builders, or transitive dependency graph resolution.")

(.def (SlsaUnsignedProvenanceCountermodel @ SlsaHermeticProvenanceModel)
  identity: 'threat.supply-chain.slsa-hermetic-provenance.unsigned-provenance
  dropped-guard: 'slsa-provenance-signed
  step-action: "stepUnsignedProvenance"
  derive-from-transition: 'admitDeployment
  derive-action-name: 'admitNoSignatureCheck
  expected-itf-predicate: "h.deployed == true and h.deployedProvenanceSigned == false")

(.def (SlsaUnreviewedSourceCountermodel @ SlsaHermeticProvenanceModel)
  identity: 'threat.supply-chain.slsa-hermetic-provenance.unreviewed-source
  dropped-guard: 'slsa-source-digest-match
  step-action: "stepUnreviewedSource"
  derive-from-transition: 'admitDeployment
  derive-action-name: 'admitNoSourceMatch
  expected-itf-predicate: "h.deployed == true and h.deployedArtifactDigest != h.reviewedSrcDigest")

(.def (SlsaCompromisedBuilderInjectionCountermodel @ SlsaHermeticProvenanceModel)
  identity: 'threat.supply-chain.slsa-hermetic-provenance.compromised-builder-injection
  dropped-guard: 'slsa-reproducible-match
  step-action: "stepCompromisedBuilderInjection"
  derive-from-transition: 'admitDeployment
  derive-action-name: 'admitNoReproducibleCheck
  expected-itf-predicate: "h.deployed == true and h.deployedArtifactDigest != h.reviewedSrcDigest")
