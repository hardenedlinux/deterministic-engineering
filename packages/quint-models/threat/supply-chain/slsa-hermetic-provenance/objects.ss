;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; SLSA v1.0 Hermetic Build Provenance & Reproducible Multi-Builder Attestation threat model.
;;; Co-located Yuanxu unit: single source of truth alongside SlsaHermeticProvenance.qnt and README.org.
;;; Models non-falsifiable builder-signed provenance (SLSA L3), reviewed source-digest binding,
;;; and independent reproducible rebuild verification (defeating compromised-builder injection).
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export SlsaHermeticProvenanceModel)

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
  limits: "Finite two-builder SLSA L3/L4 provenance and reproducible-rebuild abstraction; does not model cryptographic signature forgery, simultaneous collusion of both independent builders, or transitive dependency graph resolution.")
