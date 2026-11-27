;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Business Extension B16 (10.191 / 10.192): Zero-Downtime AEAD Key Rotation,
;;; Forward-Secure Re-Wrapping & Cryptographic Erasure (Crypto-Shredding).
;;; Proves three key-lifecycle safety invariants:
;;;   1. Active-Epoch Write Fence: new writes never use a retired key epoch
;;;      (staleWriteViolations == 0).
;;;   2. Permanent Cryptographic Erasure: crypto-shredded epochs can never be used
;;;      for encrypt or decrypt (shredReadViolations == 0).
;;;   3. Lossless Re-Wrap Parity: envelope re-wrapping strictly preserves plaintext
;;;      SHA-256 digest (rewrapMutationViolations == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export KeyRotationCryptoShreddingModel
        StaleEpochWriteCountermodel
        ShreddedKeyUseCountermodel
        MutatedRewrapCountermodel)

(.def (KeyRotationCryptoShreddingModel @ ThreatModel.)
  identity: 'engineering.defense.key-rotation-crypto-shredding
  family: 'engineering.defense.key-rotation-crypto-shredding
  title: "Zero-Downtime AEAD Key Rotation & Cryptographic Erasure"
  subdomain: 'quint.engineering.defense
  papers:
  '(("M. Bellare & B. Yee (CT-RSA 2003)"
     "Forward-Security in Private-Key Cryptography — key-epoch evolution and zeroization.")
    ("NIST SP 800-57 & GDPR Article 17 Cryptographic Erasure"
     "Zero-downtime envelope re-wrapping and crypto-shredding over immutable audit logs.")
    ("Deterministic Engineering (10.191 / 10.192)"
     "Multi-epoch AES-256-GCM key rings resolving immutable Merkle audit logs vs. right-to-erasure."))
  quint-module: "key_rotation_crypto_shredding"
  quint-file: "KeyRotationCryptoShredding.qnt"
  domain-dir: "engineering/defense/key-rotation-crypto-shredding"
  verify-depth: 10
  countermodel-depth: 6
  rules:
  '((key-rotation-safe DE-KRCS-SAFE quint)
    (key-rotation-countermodel DE-KRCS-COUNTER quint))
  dependencies:
  '((DE-KRCS-SAFE source)
    (DE-KRCS-SAFE profile)
    (DE-KRCS-SAFE method)
    (DE-KRCS-COUNTER source)
    (DE-KRCS-COUNTER profile)
    (DE-KRCS-COUNTER method))
  invariant: "Cryptographic envelope operations require active write epoch (staleWriteViolations == 0), non-shredded key epoch (shredReadViolations == 0), and verified plaintext digest preservation (rewrapMutationViolations == 0)."
  parameters: '()
  state:
  '((activeEpoch "int" "1")
    (writeEpoch "int" "1")
    (epoch1Shredded "bool" "false")
    (digestPreserved "bool" "false")
    (safeOps "int" "0")
    (staleWriteViolations "int" "0")
    (shredReadViolations "int" "0")
    (rewrapMutationViolations "int" "0"))
  guards:
  '((require-active-write-epoch (= (. h writeEpoch) (. h activeEpoch)))
    (require-not-shredded (not (and (= (. h writeEpoch) 1) (. h epoch1Shredded))))
    (require-digest-preserved (. h digestPreserved)))
  transitions:
  '((rotateToEpoch2
      (action rotateToEpoch2 ()
        (if (= (. h activeEpoch) 1)
          (set-h (activeEpoch 2))
          (keep-h))))
    (selectEpoch2Write
      (action selectEpoch2Write ()
        (if (and (= (. h activeEpoch) 2) (= (. h writeEpoch) 1))
          (set-h (writeEpoch 2))
          (keep-h))))
    (shredEpoch1Key
      (action shredEpoch1Key ()
        (if (not (. h epoch1Shredded))
          (set-h (epoch1Shredded #t))
          (keep-h))))
    (verifyPlaintextDigest
      (action verifyPlaintextDigest ()
        (if (not (. h digestPreserved))
          (set-h (digestPreserved #t))
          (keep-h))))
    (commitCryptoOp
      (action commitCryptoOp ()
        (if (and (< (. h safeOps) 2)
                 (guard require-active-write-epoch (= (. h writeEpoch) (. h activeEpoch)))
                 (guard require-not-shredded (not (and (= (. h writeEpoch) 1) (. h epoch1Shredded))))
                 (guard require-digest-preserved (. h digestPreserved)))
          (set-h (safeOps (+ (. h safeOps) 1))
                 (staleWriteViolations
                   (if (= (. h writeEpoch) (. h activeEpoch))
                     (. h staleWriteViolations)
                     (+ (. h staleWriteViolations) 1)))
                 (shredReadViolations
                   (if (not (and (= (. h writeEpoch) 1) (. h epoch1Shredded)))
                     (. h shredReadViolations)
                     (+ (. h shredReadViolations) 1)))
                 (rewrapMutationViolations
                   (if (. h digestPreserved)
                     (. h rewrapMutationViolations)
                     (+ (. h rewrapMutationViolations) 1))))
          (keep-h))))
    (step
      (action step ()
        (any rotateToEpoch2 selectEpoch2Write shredEpoch1Key
             verifyPlaintextDigest commitCryptoOp))))
  safety:
  '(and (= (. h staleWriteViolations) 0)
        (= (. h shredReadViolations) 0)
        (= (. h rewrapMutationViolations) 0))
  traces:
  '((cleanKeyRotationTest
      (run cleanKeyRotationTest
        (then init rotateToEpoch2 selectEpoch2Write shredEpoch1Key verifyPlaintextDigest commitCryptoOp
              (all (assert safety)
                   (assert (= (. h safeOps) 1))
                   (keep-h)))))
    (staleWriteViolatesSafetyTest
      (run staleWriteViolatesSafetyTest
        (then init rotateToEpoch2 verifyPlaintextDigest commitOpStaleWrite
              (all (assert (not safety))
                   (assert (> (. h staleWriteViolations) 0))
                   (keep-h)))))
    (shreddedKeyViolatesSafetyTest
      (run shreddedKeyViolatesSafetyTest
        (then init shredEpoch1Key verifyPlaintextDigest commitOpShredded
              (all (assert (not safety))
                   (assert (> (. h shredReadViolations) 0))
                   (keep-h)))))
    (mutatedRewrapViolatesSafetyTest
      (run mutatedRewrapViolatesSafetyTest
        (then init commitOpMutated
              (all (assert (not safety))
                   (assert (> (. h rewrapMutationViolations) 0))
                   (keep-h))))))
  countermodels:
  (list StaleEpochWriteCountermodel
        ShreddedKeyUseCountermodel
        MutatedRewrapCountermodel)
  limits: "Bounded 2-epoch rotation and erasure abstraction; arbitrary epoch numbers, tenant AAD isolation, and Merkle root preservation are proved unboundedly in KeyRotationAndCryptoShredding.lean.")

(.def (StaleEpochWriteCountermodel @ KeyRotationCryptoShreddingModel)
  identity: 'engineering.defense.key-rotation-crypto-shredding.stale-write
  dropped-guard: 'require-active-write-epoch
  step-action: "stepStaleWrite"
  derive-from-transition: 'commitCryptoOp
  derive-action-name: 'commitOpStaleWrite
  expected-itf-predicate: "h.staleWriteViolations > 0")

(.def (ShreddedKeyUseCountermodel @ KeyRotationCryptoShreddingModel)
  identity: 'engineering.defense.key-rotation-crypto-shredding.shredded-use
  dropped-guard: 'require-not-shredded
  step-action: "stepShreddedUse"
  derive-from-transition: 'commitCryptoOp
  derive-action-name: 'commitOpShredded
  expected-itf-predicate: "h.shredReadViolations > 0")

(.def (MutatedRewrapCountermodel @ KeyRotationCryptoShreddingModel)
  identity: 'engineering.defense.key-rotation-crypto-shredding.mutated-rewrap
  dropped-guard: 'require-digest-preserved
  step-action: "stepMutatedRewrap"
  derive-from-transition: 'commitCryptoOp
  derive-action-name: 'commitOpMutated
  expected-itf-predicate: "h.rewrapMutationViolations > 0")
