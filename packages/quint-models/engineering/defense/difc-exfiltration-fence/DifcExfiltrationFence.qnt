// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.difc-exfiltration-fence
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel forbid-secret-to-public-sink step=stepSecretExfiltration max-steps=6 itf="h.exfiltrationViolations > 0"
// @countermodel forbid-untrusted-control-flow step=stepControlHijack max-steps=6 itf="h.controlHijackViolations > 0"
// @countermodel require-cap-and-sanitizer-for-declassify step=stepUnauthorizedDeclass max-steps=6 itf="h.unauthorizedDeclassViolations > 0"
// Limits: Finite single-value confidentiality/integrity lattice and declassification abstraction; does not model timing/length covert channels, steganographic encoding inside allowed public fields, or hardware side channels.
module difc_exfiltration_fence {
  type State = { secretRead: bool, untrustedInputRead: bool, valueTaintedSecret: bool, controlTaintedUntrusted: bool, hasDeclassCap: bool, sanitizerPassed: bool, declassifiedClean: bool, exfiltrationViolations: int, controlHijackViolations: int, unauthorizedDeclassViolations: int, safePublicSinks: int }
  var h: State
  action init = h' = { secretRead: false, untrustedInputRead: false, valueTaintedSecret: false, controlTaintedUntrusted: false, hasDeclassCap: false, sanitizerPassed: false, declassifiedClean: false, exfiltrationViolations: 0, controlHijackViolations: 0, unauthorizedDeclassViolations: 0, safePublicSinks: 0 }
  action readSecretSource = if (not(h.secretRead)) h' = h.with("secretRead", true).with("valueTaintedSecret", true) else h' = h
  action readUntrustedWeb = if (not(h.untrustedInputRead)) h' = h.with("untrustedInputRead", true).with("controlTaintedUntrusted", true) else h' = h
  action grantDeclassCap = if (not(h.hasDeclassCap)) h' = h.with("hasDeclassCap", true) else h' = h
  action runDeterministicSanitizer = if ((h.valueTaintedSecret and not(h.sanitizerPassed))) h' = h.with("sanitizerPassed", true) else h' = h
  action useTrustedControlTarget = if (h.controlTaintedUntrusted) h' = h.with("controlTaintedUntrusted", false) else h' = h
  action declassifyValue = if ((h.valueTaintedSecret and not(h.declassifiedClean) and (h.hasDeclassCap and h.sanitizerPassed))) h' = h.with("declassifiedClean", true).with("valueTaintedSecret", false).with("unauthorizedDeclassViolations", if ((h.hasDeclassCap and h.sanitizerPassed)) h.unauthorizedDeclassViolations else (h.unauthorizedDeclassViolations + 1)) else h' = h
  action emitToPublicSink = if ((not(h.valueTaintedSecret) and not(h.controlTaintedUntrusted))) h' = h.with("safePublicSinks", (h.safePublicSinks + 1)).with("exfiltrationViolations", if (not(h.valueTaintedSecret)) h.exfiltrationViolations else (h.exfiltrationViolations + 1)).with("controlHijackViolations", if (not(h.controlTaintedUntrusted)) h.controlHijackViolations else (h.controlHijackViolations + 1)) else h' = h
  action step = any { readSecretSource, readUntrustedWeb, grantDeclassCap, runDeterministicSanitizer, useTrustedControlTarget, declassifyValue, emitToPublicSink }
  val safety = (h.exfiltrationViolations == 0 and h.controlHijackViolations == 0 and h.unauthorizedDeclassViolations == 0)
  // Countermodel engineering.defense.difc-exfiltration-fence.secret-exfiltration (dropped guard: forbid-secret-to-public-sink)
  action emitExfiltrating = if ((true and not(h.controlTaintedUntrusted))) h' = h.with("safePublicSinks", (h.safePublicSinks + 1)).with("exfiltrationViolations", if (not(h.valueTaintedSecret)) h.exfiltrationViolations else (h.exfiltrationViolations + 1)).with("controlHijackViolations", if (not(h.controlTaintedUntrusted)) h.controlHijackViolations else (h.controlHijackViolations + 1)) else h' = h
  action stepSecretExfiltration = any { step, emitExfiltrating }
  // Countermodel engineering.defense.difc-exfiltration-fence.control-hijack (dropped guard: forbid-untrusted-control-flow)
  action emitHijackedControl = if ((not(h.valueTaintedSecret) and true)) h' = h.with("safePublicSinks", (h.safePublicSinks + 1)).with("exfiltrationViolations", if (not(h.valueTaintedSecret)) h.exfiltrationViolations else (h.exfiltrationViolations + 1)).with("controlHijackViolations", if (not(h.controlTaintedUntrusted)) h.controlHijackViolations else (h.controlHijackViolations + 1)) else h' = h
  action stepControlHijack = any { step, emitHijackedControl }
  // Countermodel engineering.defense.difc-exfiltration-fence.unauthorized-declass (dropped guard: require-cap-and-sanitizer-for-declassify)
  action declassifyUnauthorized = if ((h.valueTaintedSecret and not(h.declassifiedClean) and true)) h' = h.with("declassifiedClean", true).with("valueTaintedSecret", false).with("unauthorizedDeclassViolations", if ((h.hasDeclassCap and h.sanitizerPassed)) h.unauthorizedDeclassViolations else (h.unauthorizedDeclassViolations + 1)) else h' = h
  action stepUnauthorizedDeclass = any { step, declassifyUnauthorized }
  run auditedDeclassAndSafePublicEmitTest = init.then(readSecretSource).then(readUntrustedWeb).then(grantDeclassCap).then(runDeterministicSanitizer).then(declassifyValue).then(useTrustedControlTarget).then(emitToPublicSink).then(all { assert(safety), assert(h.safePublicSinks == 1), assert(h.declassifiedClean), h' = h })
  run secretExfiltrationViolatesSafetyTest = init.then(readSecretSource).then(emitExfiltrating).then(all { assert(not(safety)), assert(h.exfiltrationViolations > 0), h' = h })
  run controlHijackViolatesSafetyTest = init.then(readUntrustedWeb).then(emitHijackedControl).then(all { assert(not(safety)), assert(h.controlHijackViolations > 0), h' = h })
  run unauthorizedDeclassViolatesSafetyTest = init.then(readSecretSource).then(declassifyUnauthorized).then(all { assert(not(safety)), assert(h.unauthorizedDeclassViolations > 0), h' = h })
}
