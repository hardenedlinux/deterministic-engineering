;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Business Extension B15 (10.189 / 10.190): Confidential Compute / Hardware TEE
;;; Enclave Attestation & Zero-Trust Measured Key-Release.
;;; Proves three hardware-enclave key-release safety invariants:
;;;   1. Debug Lockout: production M3 keys are never released to debug-enabled
;;;      enclaves (debugLeakViolations == 0).
;;;   2. Measurement Pinning: running enclave MRENCLAVE/RTMR must match the B14
;;;      verified artifact digest (measurementViolations == 0).
;;;   3. TCB Floor & Fresh Nonce: firmware TCB SVN floor and fresh anti-replay
;;;      nonce must both hold prior to key release (tcbOrNonceViolations == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export ConfidentialEnclaveAttestationModel
        DebugEnclaveCountermodel
        UnmeasuredEnclaveCountermodel
        StaleTcbNonceCountermodel)

(.def (ConfidentialEnclaveAttestationModel @ ThreatModel.)
  identity: 'engineering.defense.confidential-enclave-attestation
  family: 'engineering.defense.confidential-enclave-attestation
  title: "Confidential Compute / Hardware TEE Enclave Attestation & Key-Release"
  subdomain: 'quint.engineering.defense
  papers:
  '(("V. Costan & S. Devadas (IACR ePrint 2016/086)"
     "Intel SGX Explained — remote attestation quotes, debug-mode lockout, and TCB SVN anti-rollback.")
    ("AMD SEV-SNP & Intel TDX Architecture Specifications"
     "Hardware-measured launch digests and challenge-nonce remote attestation for zero-trust key release.")
    ("Deterministic Engineering (10.189 / 10.190)"
     "End-to-end B14 reproducible artifact to B15 measured TEE enclave key-release boundary."))
  quint-module: "confidential_enclave_attestation"
  quint-file: "ConfidentialEnclaveAttestation.qnt"
  domain-dir: "engineering/defense/confidential-enclave-attestation"
  verify-depth: 10
  countermodel-depth: 6
  rules:
  '((enclave-attestation-safe DE-CEA-SAFE quint)
    (enclave-attestation-countermodel DE-CEA-COUNTER quint))
  dependencies:
  '((DE-CEA-SAFE source)
    (DE-CEA-SAFE profile)
    (DE-CEA-SAFE method)
    (DE-CEA-COUNTER source)
    (DE-CEA-COUNTER profile)
    (DE-CEA-COUNTER method))
  invariant: "Production M3 key release requires debug-mode lockout (debugLeakViolations == 0), measured binary parity (measurementViolations == 0), and TCB SVN floor plus fresh challenge nonce (tcbOrNonceViolations == 0)."
  parameters: '()
  state:
  '((debugDisabled "bool" "false")
    (measurementMatched "bool" "false")
    (tcbFloorMet "bool" "false")
    (freshNonceBound "bool" "false")
    (keysReleased "int" "0")
    (debugLeakViolations "int" "0")
    (measurementViolations "int" "0")
    (tcbOrNonceViolations "int" "0"))
  guards:
  '((require-debug-disabled (. h debugDisabled))
    (require-measurement-matched (. h measurementMatched))
    (require-tcb-and-nonce (and (. h tcbFloorMet) (. h freshNonceBound))))
  transitions:
  '((lockDebugMode
      (action lockDebugMode ()
        (if (not (. h debugDisabled))
          (set-h (debugDisabled #t))
          (keep-h))))
    (verifyEnclaveMeasurement
      (action verifyEnclaveMeasurement ()
        (if (not (. h measurementMatched))
          (set-h (measurementMatched #t))
          (keep-h))))
    (verifyTcbSvnFloor
      (action verifyTcbSvnFloor ()
        (if (not (. h tcbFloorMet))
          (set-h (tcbFloorMet #t))
          (keep-h))))
    (bindFreshChallengeNonce
      (action bindFreshChallengeNonce ()
        (if (not (. h freshNonceBound))
          (set-h (freshNonceBound #t))
          (keep-h))))
    (releaseEnclaveKey
      (action releaseEnclaveKey ()
        (if (and (< (. h keysReleased) 2)
                 (guard require-debug-disabled (. h debugDisabled))
                 (guard require-measurement-matched (. h measurementMatched))
                 (guard require-tcb-and-nonce (and (. h tcbFloorMet) (. h freshNonceBound))))
          (set-h (keysReleased (+ (. h keysReleased) 1))
                 (debugLeakViolations
                   (if (. h debugDisabled)
                     (. h debugLeakViolations)
                     (+ (. h debugLeakViolations) 1)))
                 (measurementViolations
                   (if (. h measurementMatched)
                     (. h measurementViolations)
                     (+ (. h measurementViolations) 1)))
                 (tcbOrNonceViolations
                   (if (and (. h tcbFloorMet) (. h freshNonceBound))
                     (. h tcbOrNonceViolations)
                     (+ (. h tcbOrNonceViolations) 1))))
          (keep-h))))
    (step
      (action step ()
        (any lockDebugMode verifyEnclaveMeasurement verifyTcbSvnFloor
             bindFreshChallengeNonce releaseEnclaveKey))))
  safety:
  '(and (= (. h debugLeakViolations) 0)
        (= (. h measurementViolations) 0)
        (= (. h tcbOrNonceViolations) 0))
  traces:
  '((cleanKeyReleaseTest
      (run cleanKeyReleaseTest
        (then init lockDebugMode verifyEnclaveMeasurement verifyTcbSvnFloor
              bindFreshChallengeNonce releaseEnclaveKey
              (all (assert safety)
                   (assert (= (. h keysReleased) 1))
                   (keep-h)))))
    (debugEnclaveViolatesSafetyTest
      (run debugEnclaveViolatesSafetyTest
        (then init verifyEnclaveMeasurement verifyTcbSvnFloor bindFreshChallengeNonce releaseKeyDebug
              (all (assert (not safety))
                   (assert (> (. h debugLeakViolations) 0))
                   (keep-h)))))
    (unmeasuredEnclaveViolatesSafetyTest
      (run unmeasuredEnclaveViolatesSafetyTest
        (then init lockDebugMode verifyTcbSvnFloor bindFreshChallengeNonce releaseKeyUnmeasured
              (all (assert (not safety))
                   (assert (> (. h measurementViolations) 0))
                   (keep-h)))))
    (staleTcbNonceViolatesSafetyTest
      (run staleTcbNonceViolatesSafetyTest
        (then init lockDebugMode verifyEnclaveMeasurement releaseKeyStaleTcb
              (all (assert (not safety))
                   (assert (> (. h tcbOrNonceViolations) 0))
                   (keep-h))))))
  countermodels:
  (list DebugEnclaveCountermodel
        UnmeasuredEnclaveCountermodel
        StaleTcbNonceCountermodel)
  limits: "Bounded 2-key-release abstraction over debug lockout, measurement pinning, TCB floor, and nonce freshness; unbounded B14->B15 composition and arbitrary TCB SVN floors are proved in ConfidentialEnclaveAttestation.lean.")

(.def (DebugEnclaveCountermodel @ ConfidentialEnclaveAttestationModel)
  identity: 'engineering.defense.confidential-enclave-attestation.debug-enclave
  dropped-guard: 'require-debug-disabled
  step-action: "stepDebugEnclave"
  derive-from-transition: 'releaseEnclaveKey
  derive-action-name: 'releaseKeyDebug
  expected-itf-predicate: "h.debugLeakViolations > 0")

(.def (UnmeasuredEnclaveCountermodel @ ConfidentialEnclaveAttestationModel)
  identity: 'engineering.defense.confidential-enclave-attestation.unmeasured-enclave
  dropped-guard: 'require-measurement-matched
  step-action: "stepUnmeasuredEnclave"
  derive-from-transition: 'releaseEnclaveKey
  derive-action-name: 'releaseKeyUnmeasured
  expected-itf-predicate: "h.measurementViolations > 0")

(.def (StaleTcbNonceCountermodel @ ConfidentialEnclaveAttestationModel)
  identity: 'engineering.defense.confidential-enclave-attestation.stale-tcb-nonce
  dropped-guard: 'require-tcb-and-nonce
  step-action: "stepStaleTcbNonce"
  derive-from-transition: 'releaseEnclaveKey
  derive-action-name: 'releaseKeyStaleTcb
  expected-itf-predicate: "h.tcbOrNonceViolations > 0")
