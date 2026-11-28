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
(export KeyRotationCryptoShreddingModel)

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
  limits: "Bounded 2-epoch rotation and erasure abstraction; arbitrary epoch numbers, tenant AAD isolation, and Merkle root preservation are proved unboundedly in KeyRotationAndCryptoShredding.lean.")
