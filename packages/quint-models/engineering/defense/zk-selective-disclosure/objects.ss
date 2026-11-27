;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Business Extension B18 (10.195 / 10.196): Verifiable Zero-Knowledge Selective-Disclosure
;;; Compliance Proofs (RFC 3526 MODP-2048 Schnorr Sigma NIZK + Salted Merkle Tree).
;;; Proves three privacy-preserving compliance safety invariants:
;;;   1. Anti-Over-Disclosure Fence: no confidential/PII field is exposed in plaintext
;;;      inside an admitted selective disclosure (overDisclosureViolations == 0).
;;;   2. Fiat-Shamir Sigma Soundness: admission requires a valid Schnorr Sigma proof
;;;      (forgedSigmaViolations == 0).
;;;   3. Single-Use Nullifier Anti-Replay: every admitted proof consumes a fresh
;;;      unspent nullifier (nullifierReplayViolations == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export ZkSelectiveDisclosureModel)

(.def (ZkSelectiveDisclosureModel @ ThreatModel.)
  identity: 'engineering.defense.zk-selective-disclosure
  family: 'engineering.defense.zk-selective-disclosure
  title: "Zero-Knowledge Selective-Disclosure Compliance Proofs"
  subdomain: 'quint.engineering.defense
  papers:
  '(("C.-P. Schnorr (CRYPTO 1989) & A. Fiat / A. Shamir (CRYPTO 1986)"
     "Non-interactive zero-knowledge proofs of discrete-log knowledge via Fiat-Shamir transform.")
    ("IETF SD-JWT / Salted Merkle Selective Disclosure"
     "Privacy-preserving selective attribute opening without disclosing hidden confidential claims.")
    ("Deterministic Engineering (10.195 / 10.196)"
     "RFC 3526 MODP-2048 Schnorr Sigma NIZK, anti-over-disclosure fencing, and nullifier anti-replay."))
  quint-module: "zk_selective_disclosure"
  quint-file: "ZkSelectiveDisclosure.qnt"
  domain-dir: "engineering/defense/zk-selective-disclosure"
  rules:
  '((zk-disclosure-safe DE-ZKSD-SAFE quint)
    (zk-disclosure-countermodel DE-ZKSD-COUNTER quint))
  dependencies:
  '((DE-ZKSD-SAFE source)
    (DE-ZKSD-SAFE profile)
    (DE-ZKSD-SAFE method)
    (DE-ZKSD-COUNTER source)
    (DE-ZKSD-COUNTER profile)
    (DE-ZKSD-COUNTER method))
  invariant: "Zero-knowledge selective-disclosure admission forbids confidential field over-disclosure (overDisclosureViolations == 0), requires valid Schnorr Sigma verification (forgedSigmaViolations == 0), and enforces fresh single-use nullifier consumption (nullifierReplayViolations == 0)."
  limits: "Bounded selective-disclosure and single-slot nullifier freshness abstraction; unbounded forbidden/required attribute lists, challenge-nonce binding, and commitment roots are proved in ZeroKnowledgeSelectiveDisclosure.lean.")
