// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.epistemic-state-lattice
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel no-fallback-on-defect step=stepFallbackOnDefect max-steps=8 itf="h.bodyPresent == false and h.status == 3"
// @countermodel no-violation-on-pending step=stepViolationOnPending max-steps=8 itf="h.status == 4 and (h.methodDone == false or h.scopeKnown == false)"
// @countermodel preserve-conflict-no-lww step=stepConflictLww max-steps=8 itf="h.hasAllow == true and h.hasDeny == true and h.conflictResolved == false and h.status == 3"
// Limits: Finite six-state epistemic abstraction (0=SetupDefect, 1=PendingMethod, 2=PendingScope, 3=Proven, 4=Refuted, 5=Conflict); does not model cryptographic signature verification or external authority transport.
module epistemic_state_lattice {
  type State = { bodyPresent: bool, methodDone: bool, scopeKnown: bool, hasAllow: bool, hasDeny: bool, conflictResolved: bool, status: int }
  var h: State
  action init = h' = { bodyPresent: false, methodDone: false, scopeKnown: false, hasAllow: false, hasDeny: false, conflictResolved: false, status: 0 }
  action supplyBody = if (not(h.bodyPresent)) h' = h.with("bodyPresent", true).with("status", if (h.status == 0) 1 else h.status) else h' = h
  action completeMethod = if (not(h.methodDone)) h' = h.with("methodDone", true).with("status", if (h.status == 1) 2 else h.status) else h' = h
  action establishScope = if (not(h.scopeKnown)) h' = h.with("scopeKnown", true) else h' = h
  action recordAllow = if (not(h.hasAllow)) h' = h.with("hasAllow", true).with("status", if (h.hasDeny) 5 else h.status) else h' = h
  action recordDeny = if (not(h.hasDeny)) h' = h.with("hasDeny", true).with("status", if (h.hasAllow) 5 else h.status) else h' = h
  action authorizeConflictResolution = if ((h.hasAllow and h.hasDeny and not(h.conflictResolved))) h' = h.with("conflictResolved", true) else h' = h
  action concludeProven = if ((h.bodyPresent and h.methodDone and h.scopeKnown and h.hasAllow and (not(h.hasDeny) or h.conflictResolved))) h' = h.with("status", 3) else h' = h
  action concludeRefuted = if ((h.bodyPresent and (h.methodDone and h.scopeKnown) and h.hasDeny and (not(h.hasAllow) or h.conflictResolved))) h' = h.with("status", 4) else h' = h
  action step = any { supplyBody, completeMethod, establishScope, recordAllow, recordDeny, authorizeConflictResolution, concludeProven, concludeRefuted }
  val safety = ((h.bodyPresent or (h.status != 3 and h.status != 4)) and ((h.methodDone and h.scopeKnown) or (h.status != 3 and h.status != 4)) and (not((h.hasAllow and h.hasDeny)) or h.conflictResolved or (h.status != 3 and h.status != 4)))
  // Countermodel engineering.defense.epistemic-state-lattice.fallback-on-defect (dropped guard: no-fallback-on-defect)
  action concludeProvenIgnoreDefect = if ((true and h.methodDone and h.scopeKnown and h.hasAllow and (not(h.hasDeny) or h.conflictResolved))) h' = h.with("status", 3) else h' = h
  action stepFallbackOnDefect = any { step, concludeProvenIgnoreDefect }
  // Countermodel engineering.defense.epistemic-state-lattice.violation-on-pending (dropped guard: no-violation-on-pending)
  action concludeRefutedWhilePending = if ((h.bodyPresent and true and h.hasDeny and (not(h.hasAllow) or h.conflictResolved))) h' = h.with("status", 4) else h' = h
  action stepViolationOnPending = any { step, concludeRefutedWhilePending }
  // Countermodel engineering.defense.epistemic-state-lattice.conflict-lww (dropped guard: preserve-conflict-no-lww)
  action concludeProvenLww = if ((h.bodyPresent and h.methodDone and h.scopeKnown and h.hasAllow and true)) h' = h.with("status", 3) else h' = h
  action stepConflictLww = any { step, concludeProvenLww }
  run validProvenTest = init.then(supplyBody).then(completeMethod).then(establishScope).then(recordAllow).then(concludeProven).then(all { assert(safety), assert(h.status == 3), h' = h })
  run conflictPreservedUntilResolvedTest = init.then(supplyBody).then(completeMethod).then(establishScope).then(recordAllow).then(recordDeny).then(all { assert(safety), assert(h.status == 5), h' = h }).then(authorizeConflictResolution).then(concludeProven).then(all { assert(safety), assert(h.status == 3), h' = h })
  run fallbackOnDefectViolatesSafetyTest = init.then(completeMethod).then(establishScope).then(recordAllow).then(concludeProvenIgnoreDefect).then(all { assert(not(safety)), assert(not(h.bodyPresent)), assert(h.status == 3), h' = h })
  run violationOnPendingViolatesSafetyTest = init.then(supplyBody).then(recordDeny).then(concludeRefutedWhilePending).then(all { assert(not(safety)), assert(h.status == 4), h' = h })
  run conflictLwwViolatesSafetyTest = init.then(supplyBody).then(completeMethod).then(establishScope).then(recordAllow).then(recordDeny).then(concludeProvenLww).then(all { assert(not(safety)), assert(h.hasAllow), assert(h.hasDeny), assert(not(h.conflictResolved)), assert(h.status == 3), h' = h })
}
