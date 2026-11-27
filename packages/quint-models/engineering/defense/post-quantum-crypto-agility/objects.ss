;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Business Extension B17 (10.193 / 10.194): Post-Quantum Hybrid Cryptographic Agility,
;;; Anti-Algorithm-Downgrade & Stateful Hash-Based OTS Leaf Anti-Reuse.
;;; Proves three post-quantum transition safety invariants:
;;;   1. Anti-Algorithm-Downgrade Floor: hybrid suite level >= 2 is required for
;;;      envelope admission (downgradeViolations == 0).
;;;   2. Dual-AND Hybrid Combiner: BOTH classical (Ed25519) AND post-quantum
;;;      (Lamport-Diffie OTS Merkle) legs must verify (singleLegBypassViolations == 0).
;;;   3. Stateful OTS Leaf Anti-Reuse: each accepted hybrid envelope requires a fresh
;;;      unspent OTS leaf and immediately consumes it (otsReuseViolations == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export PostQuantumCryptoAgilityModel
        SuiteDowngradeCountermodel
        SingleLegBypassCountermodel
        OtsLeafReuseCountermodel)

(.def (PostQuantumCryptoAgilityModel @ ThreatModel.)
  identity: 'engineering.defense.post-quantum-crypto-agility
  family: 'engineering.defense.post-quantum-crypto-agility
  title: "Post-Quantum Hybrid Cryptographic Agility & Anti-Downgrade"
  subdomain: 'quint.engineering.defense
  papers:
  '(("L. Lamport (SRI Technical Report, 1979) & R. Merkle (CRYPTO 1989)"
     "Hash-based one-time signatures and stateful Merkle signature trees.")
    ("N. Bindel, U. Herath, M. McKague & D. Stebila (PQCrypto 2017)"
     "Transitioning to a Quantum-Resistant Public Key Infrastructure — Dual-AND hybrid combiners.")
    ("Deterministic Engineering (10.193 / 10.194)"
     "Hybrid Ed25519 + Lamport-Diffie OTS Merkle agility with anti-downgrade and OTS leaf anti-reuse."))
  quint-module: "post_quantum_crypto_agility"
  quint-file: "PostQuantumCryptoAgility.qnt"
  domain-dir: "engineering/defense/post-quantum-crypto-agility"
  verify-depth: 10
  countermodel-depth: 6
  rules:
  '((pq-agility-safe DE-PQCA-SAFE quint)
    (pq-agility-countermodel DE-PQCA-COUNTER quint))
  dependencies:
  '((DE-PQCA-SAFE source)
    (DE-PQCA-SAFE profile)
    (DE-PQCA-SAFE method)
    (DE-PQCA-COUNTER source)
    (DE-PQCA-COUNTER profile)
    (DE-PQCA-COUNTER method))
  invariant: "Hybrid certificate admission enforces hybrid PQ suite floor (downgradeViolations == 0), Dual-AND classical+PQ leg verification (singleLegBypassViolations == 0), and single-use stateful OTS leaf freshness (otsReuseViolations == 0)."
  parameters: '()
  state:
  '((suiteLevel "int" "2")
    (classicalLegValid "bool" "false")
    (pqLegValid "bool" "false")
    (otsLeafFresh "bool" "false")
    (verifiedCerts "int" "0")
    (downgradeViolations "int" "0")
    (singleLegBypassViolations "int" "0")
    (otsReuseViolations "int" "0"))
  guards:
  '((require-hybrid-suite-floor (>= (. h suiteLevel) 2))
    (require-dual-and-legs (and (. h classicalLegValid) (. h pqLegValid)))
    (require-fresh-ots-leaf (. h otsLeafFresh)))
  transitions:
  '((attemptSuiteDowngrade
      (action attemptSuiteDowngrade ()
        (if (= (. h suiteLevel) 2)
          (set-h (suiteLevel 1))
          (keep-h))))
    (restoreHybridSuite
      (action restoreHybridSuite ()
        (if (= (. h suiteLevel) 1)
          (set-h (suiteLevel 2))
          (keep-h))))
    (verifyClassicalLeg
      (action verifyClassicalLeg ()
        (if (not (. h classicalLegValid))
          (set-h (classicalLegValid #t))
          (keep-h))))
    (verifyPqLeg
      (action verifyPqLeg ()
        (if (not (. h pqLegValid))
          (set-h (pqLegValid #t))
          (keep-h))))
    (allocateFreshOtsLeaf
      (action allocateFreshOtsLeaf ()
        (if (not (. h otsLeafFresh))
          (set-h (otsLeafFresh #t))
          (keep-h))))
    (acceptHybridEnvelope
      (action acceptHybridEnvelope ()
        (if (and (< (. h verifiedCerts) 2)
                 (guard require-hybrid-suite-floor (>= (. h suiteLevel) 2))
                 (guard require-dual-and-legs (and (. h classicalLegValid) (. h pqLegValid)))
                 (guard require-fresh-ots-leaf (. h otsLeafFresh)))
          (set-h (verifiedCerts (+ (. h verifiedCerts) 1))
                 (otsLeafFresh #f)
                 (downgradeViolations
                   (if (>= (. h suiteLevel) 2)
                     (. h downgradeViolations)
                     (+ (. h downgradeViolations) 1)))
                 (singleLegBypassViolations
                   (if (and (. h classicalLegValid) (. h pqLegValid))
                     (. h singleLegBypassViolations)
                     (+ (. h singleLegBypassViolations) 1)))
                 (otsReuseViolations
                   (if (. h otsLeafFresh)
                     (. h otsReuseViolations)
                     (+ (. h otsReuseViolations) 1))))
          (keep-h))))
    (step
      (action step ()
        (any attemptSuiteDowngrade restoreHybridSuite verifyClassicalLeg
             verifyPqLeg allocateFreshOtsLeaf acceptHybridEnvelope))))
  safety:
  '(and (= (. h downgradeViolations) 0)
        (= (. h singleLegBypassViolations) 0)
        (= (. h otsReuseViolations) 0))
  traces:
  '((cleanHybridEnvelopeTest
      (run cleanHybridEnvelopeTest
        (then init verifyClassicalLeg verifyPqLeg allocateFreshOtsLeaf acceptHybridEnvelope
              (all (assert safety)
                   (assert (= (. h verifiedCerts) 1))
                   (assert (not (. h otsLeafFresh)))
                   (keep-h)))))
    (downgradeViolatesSafetyTest
      (run downgradeViolatesSafetyTest
        (then init attemptSuiteDowngrade verifyClassicalLeg verifyPqLeg allocateFreshOtsLeaf acceptEnvelopeDowngraded
              (all (assert (not safety))
                   (assert (> (. h downgradeViolations) 0))
                   (keep-h)))))
    (singleLegViolatesSafetyTest
      (run singleLegViolatesSafetyTest
        (then init verifyClassicalLeg allocateFreshOtsLeaf acceptEnvelopeSingleLeg
              (all (assert (not safety))
                   (assert (> (. h singleLegBypassViolations) 0))
                   (keep-h)))))
    (otsReuseViolatesSafetyTest
      (run otsReuseViolatesSafetyTest
        (then init verifyClassicalLeg verifyPqLeg acceptEnvelopeOtsReuse
              (all (assert (not safety))
                   (assert (> (. h otsReuseViolations) 0))
                   (keep-h))))))
  countermodels:
  (list SuiteDowngradeCountermodel
        SingleLegBypassCountermodel
        OtsLeafReuseCountermodel)
  limits: "Bounded 2-suite agility and single-slot OTS leaf freshness abstraction; arbitrary deprecated suites, domain separation tags, and unbounded Merkle OTS indices are proved in PostQuantumCryptoAgility.lean.")

(.def (SuiteDowngradeCountermodel @ PostQuantumCryptoAgilityModel)
  identity: 'engineering.defense.post-quantum-crypto-agility.suite-downgrade
  dropped-guard: 'require-hybrid-suite-floor
  step-action: "stepDowngrade"
  derive-from-transition: 'acceptHybridEnvelope
  derive-action-name: 'acceptEnvelopeDowngraded
  expected-itf-predicate: "h.downgradeViolations > 0")

(.def (SingleLegBypassCountermodel @ PostQuantumCryptoAgilityModel)
  identity: 'engineering.defense.post-quantum-crypto-agility.single-leg-bypass
  dropped-guard: 'require-dual-and-legs
  step-action: "stepSingleLeg"
  derive-from-transition: 'acceptHybridEnvelope
  derive-action-name: 'acceptEnvelopeSingleLeg
  expected-itf-predicate: "h.singleLegBypassViolations > 0")

(.def (OtsLeafReuseCountermodel @ PostQuantumCryptoAgilityModel)
  identity: 'engineering.defense.post-quantum-crypto-agility.ots-leaf-reuse
  dropped-guard: 'require-fresh-ots-leaf
  step-action: "stepOtsReuse"
  derive-from-transition: 'acceptHybridEnvelope
  derive-action-name: 'acceptEnvelopeOtsReuse
  expected-itf-predicate: "h.otsReuseViolations > 0")
