// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.confidential-enclave-attestation
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel require-debug-disabled step=stepDebugEnclave max-steps=6 itf="h.debugLeakViolations > 0"
// @countermodel require-measurement-matched step=stepUnmeasuredEnclave max-steps=6 itf="h.measurementViolations > 0"
// @countermodel require-tcb-and-nonce step=stepStaleTcbNonce max-steps=6 itf="h.tcbOrNonceViolations > 0"
// Limits: Bounded 2-key-release abstraction over debug lockout, measurement pinning, TCB floor, and nonce freshness; unbounded B14->B15 composition and arbitrary TCB SVN floors are proved in ConfidentialEnclaveAttestation.lean.
module confidential_enclave_attestation {
  type State = { debugDisabled: bool, measurementMatched: bool, tcbFloorMet: bool, freshNonceBound: bool, keysReleased: int, debugLeakViolations: int, measurementViolations: int, tcbOrNonceViolations: int }
  var h: State
  action init = h' = { debugDisabled: false, measurementMatched: false, tcbFloorMet: false, freshNonceBound: false, keysReleased: 0, debugLeakViolations: 0, measurementViolations: 0, tcbOrNonceViolations: 0 }
  action lockDebugMode = if (not(h.debugDisabled)) h' = h.with("debugDisabled", true) else h' = h
  action verifyEnclaveMeasurement = if (not(h.measurementMatched)) h' = h.with("measurementMatched", true) else h' = h
  action verifyTcbSvnFloor = if (not(h.tcbFloorMet)) h' = h.with("tcbFloorMet", true) else h' = h
  action bindFreshChallengeNonce = if (not(h.freshNonceBound)) h' = h.with("freshNonceBound", true) else h' = h
  action releaseEnclaveKey = if ((h.keysReleased < 2 and h.debugDisabled and h.measurementMatched and (h.tcbFloorMet and h.freshNonceBound))) h' = h.with("keysReleased", (h.keysReleased + 1)).with("debugLeakViolations", if (h.debugDisabled) h.debugLeakViolations else (h.debugLeakViolations + 1)).with("measurementViolations", if (h.measurementMatched) h.measurementViolations else (h.measurementViolations + 1)).with("tcbOrNonceViolations", if ((h.tcbFloorMet and h.freshNonceBound)) h.tcbOrNonceViolations else (h.tcbOrNonceViolations + 1)) else h' = h
  action step = any { lockDebugMode, verifyEnclaveMeasurement, verifyTcbSvnFloor, bindFreshChallengeNonce, releaseEnclaveKey }
  val safety = (h.debugLeakViolations == 0 and h.measurementViolations == 0 and h.tcbOrNonceViolations == 0)
  // Countermodel engineering.defense.confidential-enclave-attestation.debug-enclave (dropped guard: require-debug-disabled)
  action releaseKeyDebug = if ((h.keysReleased < 2 and true and h.measurementMatched and (h.tcbFloorMet and h.freshNonceBound))) h' = h.with("keysReleased", (h.keysReleased + 1)).with("debugLeakViolations", if (h.debugDisabled) h.debugLeakViolations else (h.debugLeakViolations + 1)).with("measurementViolations", if (h.measurementMatched) h.measurementViolations else (h.measurementViolations + 1)).with("tcbOrNonceViolations", if ((h.tcbFloorMet and h.freshNonceBound)) h.tcbOrNonceViolations else (h.tcbOrNonceViolations + 1)) else h' = h
  action stepDebugEnclave = any { step, releaseKeyDebug }
  // Countermodel engineering.defense.confidential-enclave-attestation.unmeasured-enclave (dropped guard: require-measurement-matched)
  action releaseKeyUnmeasured = if ((h.keysReleased < 2 and h.debugDisabled and true and (h.tcbFloorMet and h.freshNonceBound))) h' = h.with("keysReleased", (h.keysReleased + 1)).with("debugLeakViolations", if (h.debugDisabled) h.debugLeakViolations else (h.debugLeakViolations + 1)).with("measurementViolations", if (h.measurementMatched) h.measurementViolations else (h.measurementViolations + 1)).with("tcbOrNonceViolations", if ((h.tcbFloorMet and h.freshNonceBound)) h.tcbOrNonceViolations else (h.tcbOrNonceViolations + 1)) else h' = h
  action stepUnmeasuredEnclave = any { step, releaseKeyUnmeasured }
  // Countermodel engineering.defense.confidential-enclave-attestation.stale-tcb-nonce (dropped guard: require-tcb-and-nonce)
  action releaseKeyStaleTcb = if ((h.keysReleased < 2 and h.debugDisabled and h.measurementMatched and true)) h' = h.with("keysReleased", (h.keysReleased + 1)).with("debugLeakViolations", if (h.debugDisabled) h.debugLeakViolations else (h.debugLeakViolations + 1)).with("measurementViolations", if (h.measurementMatched) h.measurementViolations else (h.measurementViolations + 1)).with("tcbOrNonceViolations", if ((h.tcbFloorMet and h.freshNonceBound)) h.tcbOrNonceViolations else (h.tcbOrNonceViolations + 1)) else h' = h
  action stepStaleTcbNonce = any { step, releaseKeyStaleTcb }
  run cleanKeyReleaseTest = init.then(lockDebugMode).then(verifyEnclaveMeasurement).then(verifyTcbSvnFloor).then(bindFreshChallengeNonce).then(releaseEnclaveKey).then(all { assert(safety), assert(h.keysReleased == 1), h' = h })
  run debugEnclaveViolatesSafetyTest = init.then(verifyEnclaveMeasurement).then(verifyTcbSvnFloor).then(bindFreshChallengeNonce).then(releaseKeyDebug).then(all { assert(not(safety)), assert(h.debugLeakViolations > 0), h' = h })
  run unmeasuredEnclaveViolatesSafetyTest = init.then(lockDebugMode).then(verifyTcbSvnFloor).then(bindFreshChallengeNonce).then(releaseKeyUnmeasured).then(all { assert(not(safety)), assert(h.measurementViolations > 0), h' = h })
  run staleTcbNonceViolatesSafetyTest = init.then(lockDebugMode).then(verifyEnclaveMeasurement).then(releaseKeyStaleTcb).then(all { assert(not(safety)), assert(h.tcbOrNonceViolations > 0), h' = h })
}
