;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; R4 + R5 (10.156): Semantic-Drift-Aware LLM Memoization & Byzantine Capability-Partitioned AEAD Store.
;;; Proves three invariants when prompt-injected agents share a persistent Merkle KV backend:
;;;   1. Compromised peers lacking the partition AEAD key cannot read gold oracle rows (oracleLeaks == 0).
;;;   2. Tampered or cross-partition transplanted ciphertexts are rejected by AEAD tag + AAD (forgedVerdicts == 0).
;;;   3. Memoized LLM outputs cannot be blindly replayed after upstream M2 digest drift (driftedReplays == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export ByzantineEncryptedStoreModel
        PlaintextOracleLeakCountermodel
        ByzantineCiphertextForgeryCountermodel
        SemanticDriftBlindReplayCountermodel)

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
  verify-depth: 10
  countermodel-depth: 6
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
  parameters: '()
  state:
  '((coderCompromised "bool" "false")
    (goldEncrypted "bool" "true")
    (ciphertextTampered "bool" "false")
    (aeadVerified "bool" "true")
    (upstreamDrifted "bool" "false")
    (memoRevalidated "bool" "true")
    (oracleLeaks "int" "0")
    (forgedVerdicts "int" "0")
    (driftedReplays "int" "0"))
  guards:
  '((require-partition-aead-key (not (. h coderCompromised)))
    (require-aead-tag-and-aad (and (. h aeadVerified) (not (. h ciphertextTampered))))
    (require-m2-memo-freshness (or (not (. h upstreamDrifted)) (. h memoRevalidated))))
  transitions:
  '((injectPromptIntoCoder
      (action injectPromptIntoCoder ()
        (if (not (. h coderCompromised))
          (set-h (coderCompromised #t))
          (keep-h))))
    (tamperOrTransplantRow
      (action tamperOrTransplantRow ()
        (if (and (. h coderCompromised) (not (. h ciphertextTampered)))
          (set-h (ciphertextTampered #t)
                 (aeadVerified #f))
          (keep-h))))
    (restoreAuthenticCiphertext
      (action restoreAuthenticCiphertext ()
        (if (. h ciphertextTampered)
          (set-h (ciphertextTampered #f)
                 (aeadVerified #t))
          (keep-h))))
    (driftUpstreamManifest
      (action driftUpstreamManifest ()
        (if (not (. h upstreamDrifted))
          (set-h (upstreamDrifted #t)
                 (memoRevalidated #f))
          (keep-h))))
    (repromptDriftedStep
      (action repromptDriftedStep ()
        (if (and (. h upstreamDrifted) (not (. h memoRevalidated)))
          (set-h (memoRevalidated #t))
          (keep-h))))
    (readReviewerGold
      (action readReviewerGold ()
        (if (guard require-partition-aead-key (not (. h coderCompromised)))
          (set-h (oracleLeaks
                   (if (. h coderCompromised)
                     (+ (. h oracleLeaks) 1)
                     (. h oracleLeaks))))
          (keep-h))))
    (acceptEncryptedVerdict
      (action acceptEncryptedVerdict ()
        (if (guard require-aead-tag-and-aad (and (. h aeadVerified) (not (. h ciphertextTampered))))
          (set-h (forgedVerdicts
                   (if (or (. h ciphertextTampered) (not (. h aeadVerified)))
                     (+ (. h forgedVerdicts) 1)
                     (. h forgedVerdicts))))
          (keep-h))))
    (replayMemoizedLlmStep
      (action replayMemoizedLlmStep ()
        (if (guard require-m2-memo-freshness (or (not (. h upstreamDrifted)) (. h memoRevalidated)))
          (set-h (driftedReplays
                   (if (and (. h upstreamDrifted) (not (. h memoRevalidated)))
                     (+ (. h driftedReplays) 1)
                     (. h driftedReplays))))
          (keep-h))))
    (step
      (action step ()
        (any injectPromptIntoCoder tamperOrTransplantRow restoreAuthenticCiphertext
             driftUpstreamManifest repromptDriftedStep readReviewerGold
             acceptEncryptedVerdict replayMemoizedLlmStep))))
  safety:
  '(and (. h goldEncrypted)
        (= (. h oracleLeaks) 0)
        (= (. h forgedVerdicts) 0)
        (= (. h driftedReplays) 0))
  traces:
  '((encryptedIsolationAndDriftRevalidateSafeTest
      (run encryptedIsolationAndDriftRevalidateSafeTest
        (then init injectPromptIntoCoder tamperOrTransplantRow acceptEncryptedVerdict
              readReviewerGold restoreAuthenticCiphertext acceptEncryptedVerdict
              driftUpstreamManifest repromptDriftedStep replayMemoizedLlmStep
              (all (assert safety)
                   (assert (. h coderCompromised))
                   (assert (. h memoRevalidated))
                   (keep-h)))))
    (plaintextLeakViolatesSafetyTest
      (run plaintextLeakViolatesSafetyTest
        (then init injectPromptIntoCoder readReviewerGoldNoKeyCheck
              (all (assert (not safety))
                   (assert (> (. h oracleLeaks) 0))
                   (keep-h)))))
    (ciphertextForgeryViolatesSafetyTest
      (run ciphertextForgeryViolatesSafetyTest
        (then init injectPromptIntoCoder tamperOrTransplantRow acceptUnverifiedCiphertext
              (all (assert (not safety))
                   (assert (> (. h forgedVerdicts) 0))
                   (keep-h)))))
    (driftedReplayViolatesSafetyTest
      (run driftedReplayViolatesSafetyTest
        (then init driftUpstreamManifest replayDriftedMemoBlindly
              (all (assert (not safety))
                   (assert (> (. h driftedReplays) 0))
                   (keep-h))))))
  countermodels:
  (list PlaintextOracleLeakCountermodel
        ByzantineCiphertextForgeryCountermodel
        SemanticDriftBlindReplayCountermodel)
  limits: "Finite single-partition Byzantine AEAD confidentiality/integrity and single-step M2 semantic-drift abstraction; does not model side-channel timing attacks, compromised KMS root keys, or multi-step prompt-injection covert channels.")

(.def (PlaintextOracleLeakCountermodel @ ByzantineEncryptedStoreModel)
  identity: 'engineering.defense.byzantine-encrypted-store.plaintext-leak
  dropped-guard: 'require-partition-aead-key
  step-action: "stepPlaintextLeak"
  derive-from-transition: 'readReviewerGold
  derive-action-name: 'readReviewerGoldNoKeyCheck
  expected-itf-predicate: "h.oracleLeaks > 0")

(.def (ByzantineCiphertextForgeryCountermodel @ ByzantineEncryptedStoreModel)
  identity: 'engineering.defense.byzantine-encrypted-store.ciphertext-forgery
  dropped-guard: 'require-aead-tag-and-aad
  step-action: "stepCiphertextForgery"
  derive-from-transition: 'acceptEncryptedVerdict
  derive-action-name: 'acceptUnverifiedCiphertext
  expected-itf-predicate: "h.forgedVerdicts > 0")

(.def (SemanticDriftBlindReplayCountermodel @ ByzantineEncryptedStoreModel)
  identity: 'engineering.defense.byzantine-encrypted-store.drifted-replay
  dropped-guard: 'require-m2-memo-freshness
  step-action: "stepDriftedReplay"
  derive-from-transition: 'replayMemoizedLlmStep
  derive-action-name: 'replayDriftedMemoBlindly
  expected-itf-predicate: "h.driftedReplays > 0")
