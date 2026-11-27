// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.policy-gate-blindspot-and-cycle-confinement
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel forbid-cycle-blinded-admission step=stepCycleBlindedAdmission max-steps=6 itf="h.blindedAdmits > 0"
// @countermodel forbid-ungated-or-downgraded-admission step=stepUngatedOrDowngradedAdmission max-steps=6 itf="h.ungatedOrDowngradedAdmits > 0"
// @countermodel forbid-fat-entrypoint-admission step=stepFatEntrypointAdmission max-steps=6 itf="h.fatEntrypointAdmits > 0"
// @countermodel forbid-ci-omitted-release step=stepCiOmittedRelease max-steps=6 itf="h.ciOmittedReleases > 0"
// Limits: Finite bounded workspace policy-gate governance model (cyclicSccs <= 2, stepCount <= 12); models Cargo dev-dependency cycle blinding, per-crate policy gate coverage and fail-closed mode, thin binary/test entrypoint confinement, and CI policy-gate invocation, without modeling external registry compromise or arbitrary proc-macro code execution.
module defense_policy_gate_blindspot_and_cycle_confinement {
  type State = { cyclicSccs: int, ungatedCriticalCrates: int, fatEntrypoints: int, gateModeFailClosed: bool, ciInvokesPolicyGate: bool, blindedAdmits: int, ungatedOrDowngradedAdmits: int, fatEntrypointAdmits: int, ciOmittedReleases: int, cleanGovernedAdmits: int, stepCount: int }
  var h: State
  action init = h' = { cyclicSccs: 1, ungatedCriticalCrates: 1, fatEntrypoints: 1, gateModeFailClosed: false, ciInvokesPolicyGate: false, blindedAdmits: 0, ungatedOrDowngradedAdmits: 0, fatEntrypointAdmits: 0, ciOmittedReleases: 0, cleanGovernedAdmits: 0, stepCount: 0 }
  action introduceDevDepCycle = if ((h.stepCount < 12 and h.cyclicSccs < 2)) h' = h.with("cyclicSccs", (h.cyclicSccs + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action breakDevDepCycle = if ((h.stepCount < 12 and h.cyclicSccs > 0)) h' = h.with("cyclicSccs", (h.cyclicSccs - 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action mountCrateGateAndTighten = if ((h.stepCount < 12 and (h.ungatedCriticalCrates > 0 or not(h.gateModeFailClosed)))) h' = h.with("ungatedCriticalCrates", 0).with("gateModeFailClosed", true).with("stepCount", (h.stepCount + 1)) else h' = h
  action extractFatEntrypointToOwner = if ((h.stepCount < 12 and h.fatEntrypoints > 0)) h' = h.with("fatEntrypoints", (h.fatEntrypoints - 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action enableCiPolicyGate = if ((h.stepCount < 12 and not(h.ciInvokesPolicyGate))) h' = h.with("ciInvokesPolicyGate", true).with("stepCount", (h.stepCount + 1)) else h' = h
  action admitPatchIfPolicyHealthy = if ((h.stepCount < 12 and h.cyclicSccs == 0 and h.ungatedCriticalCrates == 0 and h.fatEntrypoints == 0 and h.gateModeFailClosed and h.ciInvokesPolicyGate)) h' = h.with("cleanGovernedAdmits", (h.cleanGovernedAdmits + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action step = any { introduceDevDepCycle, breakDevDepCycle, mountCrateGateAndTighten, extractFatEntrypointToOwner, enableCiPolicyGate, admitPatchIfPolicyHealthy }
  val safety = (h.blindedAdmits == 0 and h.ungatedOrDowngradedAdmits == 0 and h.fatEntrypointAdmits == 0 and h.ciOmittedReleases == 0 and h.cyclicSccs >= 0 and h.cyclicSccs <= 2 and h.ungatedCriticalCrates >= 0 and h.fatEntrypoints >= 0 and h.stepCount <= 12)
  // Countermodel engineering.defense.policy-gate-blindspot-and-cycle-confinement.cycle-blinded (dropped guard: forbid-cycle-blinded-admission)
  action admitWhileCycleBlinded = if ((h.stepCount < 12 and h.cyclicSccs > 0)) h' = h.with("blindedAdmits", (h.blindedAdmits + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepCycleBlindedAdmission = any { step, admitWhileCycleBlinded }
  // Countermodel engineering.defense.policy-gate-blindspot-and-cycle-confinement.ungated-or-downgraded (dropped guard: forbid-ungated-or-downgraded-admission)
  action admitUngatedOrDowngraded = if ((h.stepCount < 12 and (h.ungatedCriticalCrates > 0 or not(h.gateModeFailClosed)))) h' = h.with("ungatedOrDowngradedAdmits", (h.ungatedOrDowngradedAdmits + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepUngatedOrDowngradedAdmission = any { step, admitUngatedOrDowngraded }
  // Countermodel engineering.defense.policy-gate-blindspot-and-cycle-confinement.fat-entrypoint (dropped guard: forbid-fat-entrypoint-admission)
  action admitFatEntrypoint = if ((h.stepCount < 12 and h.fatEntrypoints > 0)) h' = h.with("fatEntrypointAdmits", (h.fatEntrypointAdmits + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepFatEntrypointAdmission = any { step, admitFatEntrypoint }
  // Countermodel engineering.defense.policy-gate-blindspot-and-cycle-confinement.ci-omitted (dropped guard: forbid-ci-omitted-release)
  action releaseWithoutCiPolicyGate = if ((h.stepCount < 12 and not(h.ciInvokesPolicyGate))) h' = h.with("ciOmittedReleases", (h.ciOmittedReleases + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepCiOmittedRelease = any { step, releaseWithoutCiPolicyGate }
  action checkPolicyHealthySafe = all { assert(safety), assert(h.cleanGovernedAdmits == 1), assert(h.cyclicSccs == 0), h' = h }
  action checkPolicyViolated = all { assert((h.blindedAdmits > 0 or h.ungatedOrDowngradedAdmits > 0 or h.fatEntrypointAdmits > 0 or h.ciOmittedReleases > 0)), assert(not(safety)), h' = h }
  run cleanGovernedWorkspaceAdmitsSafeTest = init.then(breakDevDepCycle).then(mountCrateGateAndTighten).then(extractFatEntrypointToOwner).then(enableCiPolicyGate).then(admitPatchIfPolicyHealthy).then(checkPolicyHealthySafe)
  run cycleReintroducedAndBrokenSafeTest = init.then(introduceDevDepCycle).then(breakDevDepCycle).then(breakDevDepCycle).then(mountCrateGateAndTighten).then(extractFatEntrypointToOwner).then(enableCiPolicyGate).then(admitPatchIfPolicyHealthy).then(checkPolicyHealthySafe)
  run cycleBlindedViolatesSafetyTest = init.then(admitWhileCycleBlinded).then(checkPolicyViolated)
  run ungatedOrDowngradedViolatesSafetyTest = init.then(admitUngatedOrDowngraded).then(checkPolicyViolated)
  run fatEntrypointViolatesSafetyTest = init.then(admitFatEntrypoint).then(checkPolicyViolated)
  run ciOmittedReleaseViolatesSafetyTest = init.then(releaseWithoutCiPolicyGate).then(checkPolicyViolated)
}
