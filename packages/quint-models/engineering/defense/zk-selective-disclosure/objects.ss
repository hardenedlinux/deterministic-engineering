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
(export ZkSelectiveDisclosureModel
        SecretOverDisclosureCountermodel
        ForgedSigmaProofCountermodel
        NullifierReplayCountermodel)

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
  verify-depth: 10
  countermodel-depth: 6
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
  parameters: '()
  state:
  '((secretFieldExposed "bool" "false")
    (sigmaProofValid "bool" "false")
    (nullifierFresh "bool" "false")
    (verifiedDisclosures "int" "0")
    (overDisclosureViolations "int" "0")
    (forgedSigmaViolations "int" "0")
    (nullifierReplayViolations "int" "0"))
  guards:
  '((require-no-secret-exposure (not (. h secretFieldExposed)))
    (require-valid-sigma-proof (. h sigmaProofValid))
    (require-fresh-nullifier (. h nullifierFresh)))
  transitions:
  '((exposeSecretField
      (action exposeSecretField ()
        (if (not (. h secretFieldExposed))
          (set-h (secretFieldExposed #t))
          (keep-h))))
    (redactSecretField
      (action redactSecretField ()
        (if (. h secretFieldExposed)
          (set-h (secretFieldExposed #f))
          (keep-h))))
    (verifySigmaProof
      (action verifySigmaProof ()
        (if (not (. h sigmaProofValid))
          (set-h (sigmaProofValid #t))
          (keep-h))))
    (issueFreshNullifier
      (action issueFreshNullifier ()
        (if (not (. h nullifierFresh))
          (set-h (nullifierFresh #t))
          (keep-h))))
    (admitZkDisclosure
      (action admitZkDisclosure ()
        (if (and (< (. h verifiedDisclosures) 2)
                 (guard require-no-secret-exposure (not (. h secretFieldExposed)))
                 (guard require-valid-sigma-proof (. h sigmaProofValid))
                 (guard require-fresh-nullifier (. h nullifierFresh)))
          (set-h (verifiedDisclosures (+ (. h verifiedDisclosures) 1))
                 (nullifierFresh #f)
                 (overDisclosureViolations
                   (if (not (. h secretFieldExposed))
                     (. h overDisclosureViolations)
                     (+ (. h overDisclosureViolations) 1)))
                 (forgedSigmaViolations
                   (if (. h sigmaProofValid)
                     (. h forgedSigmaViolations)
                     (+ (. h forgedSigmaViolations) 1)))
                 (nullifierReplayViolations
                   (if (. h nullifierFresh)
                     (. h nullifierReplayViolations)
                     (+ (. h nullifierReplayViolations) 1))))
          (keep-h))))
    (step
      (action step ()
        (any exposeSecretField redactSecretField verifySigmaProof
             issueFreshNullifier admitZkDisclosure))))
  safety:
  '(and (= (. h overDisclosureViolations) 0)
        (= (. h forgedSigmaViolations) 0)
        (= (. h nullifierReplayViolations) 0))
  traces:
  '((cleanZkDisclosureTest
      (run cleanZkDisclosureTest
        (then init verifySigmaProof issueFreshNullifier admitZkDisclosure
              (all (assert safety)
                   (assert (= (. h verifiedDisclosures) 1))
                   (assert (not (. h nullifierFresh)))
                   (keep-h)))))
    (overDisclosureViolatesSafetyTest
      (run overDisclosureViolatesSafetyTest
        (then init exposeSecretField verifySigmaProof issueFreshNullifier admitDisclosureOverExposed
              (all (assert (not safety))
                   (assert (> (. h overDisclosureViolations) 0))
                   (keep-h)))))
    (forgedSigmaViolatesSafetyTest
      (run forgedSigmaViolatesSafetyTest
        (then init issueFreshNullifier admitDisclosureForgedSigma
              (all (assert (not safety))
                   (assert (> (. h forgedSigmaViolations) 0))
                   (keep-h)))))
    (nullifierReplayViolatesSafetyTest
      (run nullifierReplayViolatesSafetyTest
        (then init verifySigmaProof admitDisclosureNullifierReplay
              (all (assert (not safety))
                   (assert (> (. h nullifierReplayViolations) 0))
                   (keep-h))))))
  countermodels:
  (list SecretOverDisclosureCountermodel
        ForgedSigmaProofCountermodel
        NullifierReplayCountermodel)
  limits: "Bounded selective-disclosure and single-slot nullifier freshness abstraction; unbounded forbidden/required attribute lists, challenge-nonce binding, and commitment roots are proved in ZeroKnowledgeSelectiveDisclosure.lean.")

(.def (SecretOverDisclosureCountermodel @ ZkSelectiveDisclosureModel)
  identity: 'engineering.defense.zk-selective-disclosure.over-disclosure
  dropped-guard: 'require-no-secret-exposure
  step-action: "stepOverDisclosure"
  derive-from-transition: 'admitZkDisclosure
  derive-action-name: 'admitDisclosureOverExposed
  expected-itf-predicate: "h.overDisclosureViolations > 0")

(.def (ForgedSigmaProofCountermodel @ ZkSelectiveDisclosureModel)
  identity: 'engineering.defense.zk-selective-disclosure.forged-sigma
  dropped-guard: 'require-valid-sigma-proof
  step-action: "stepForgedSigma"
  derive-from-transition: 'admitZkDisclosure
  derive-action-name: 'admitDisclosureForgedSigma
  expected-itf-predicate: "h.forgedSigmaViolations > 0")

(.def (NullifierReplayCountermodel @ ZkSelectiveDisclosureModel)
  identity: 'engineering.defense.zk-selective-disclosure.nullifier-replay
  dropped-guard: 'require-fresh-nullifier
  step-action: "stepNullifierReplay"
  derive-from-transition: 'admitZkDisclosure
  derive-action-name: 'admitDisclosureNullifierReplay
  expected-itf-predicate: "h.nullifierReplayViolations > 0")
