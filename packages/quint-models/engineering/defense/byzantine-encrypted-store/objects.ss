;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; R4 + R5 (10.156): Semantic-Drift-Aware LLM Memoization & Byzantine Capability-Partitioned AEAD Store.
;;; Proves three invariants when prompt-injected agents share a persistent Merkle KV backend:
;;;   1. Compromised peers lacking the partition AEAD key cannot read gold oracle rows (oracleLeaks == 0).
;;;   2. Tampered or cross-partition transplanted ciphertexts are rejected by AEAD tag + AAD (forgedVerdicts == 0).
;;;   3. Memoized LLM outputs cannot be blindly replayed after upstream M2 digest drift (driftedReplays == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export ByzantineEncryptedStoreModel)

(.def (ByzantineEncryptedStoreModel @ ThreatModel.)
  identity: 'engineering.defense.byzantine-encrypted-store
  family: 'engineering.defense.byzantine-encrypted-store
  title: "Byzantine AEAD-Partitioned Persistent Store & LLM Semantic-Drift Memoization"
  subdomain: 'quint.engineering.defense
  papers:
  '(("Mighty Gerbils (gerbil-persist)"
     "Row-level encryption over minimal ACID KV combined with content-addressed Merkle DAG.")
    ("J. S. Shapiro, J. M. Smith & D. J. Farber (SOSP 1999)"
     "EROS: A Capability System (pure capability isolation across shared persistent storage).")
    ("Deterministic Engineering (10.156 R4 / R5)"
     "M2 semantic-dependency manifests for stochastic LLM memoization and per-role AES-256-GCM AAD partition isolation."))
  quint-module: "byzantine_encrypted_store"
  quint-file: "ByzantineEncryptedStore.qnt"
  domain-dir: "engineering/defense/byzantine-encrypted-store"
  rules:
  '((byzantine-store-safe DE-BYZ-SAFE quint)
    (byzantine-store-countermodel DE-BYZ-COUNTER quint))
  dependencies:
  '((DE-BYZ-SAFE source)
    (DE-BYZ-SAFE profile)
    (DE-BYZ-SAFE method)
    (DE-BYZ-COUNTER source)
    (DE-BYZ-COUNTER profile)
    (DE-BYZ-COUNTER method))
  invariant: "Reviewer gold rows stay AEAD-encrypted, no compromised agent leaks gold oracles (oracleLeaks == 0), no tampered/transplanted ciphertext is accepted (forgedVerdicts == 0), and no drifted LLM memo is blindly replayed (driftedReplays == 0)."
  limits: "Finite single-partition Byzantine AEAD confidentiality/integrity and single-step M2 semantic-drift abstraction; does not model side-channel timing attacks, compromised KMS root keys, or multi-step prompt-injection covert channels.")
