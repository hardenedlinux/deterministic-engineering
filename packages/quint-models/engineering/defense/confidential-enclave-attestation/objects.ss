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
(export ConfidentialEnclaveAttestationModel)

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
  limits: "Bounded 2-key-release abstraction over debug lockout, measurement pinning, TCB floor, and nonce freshness; unbounded B14->B15 composition and arbitrary TCB SVN floors are proved in ConfidentialEnclaveAttestation.lean.")
