// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.supply-chain-provenance
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel require-lockfile-pinned step=stepSlopsquatting max-steps=6 itf="h.slopsquatViolations > 0"
// @countermodel require-no-cve-tombstone step=stepCveTombstone max-steps=6 itf="h.cveViolations > 0"
// @countermodel require-hermetic-reproducible step=stepNonReproducible max-steps=6 itf="h.reproViolations > 0"
// Limits: Bounded 2-build abstraction over lockfile pinning, CVE tombstones, and hermetic 2-builder parity; unbounded SBOM dependency lists and builder signatures are proved in SupplyChainProvenance.lean.
module supply_chain_provenance {
  type State = { lockfilePinned: bool, cveTombstoned: bool, hermeticSandbox: bool, twoBuilderMatch: bool, admittedBuilds: int, slopsquatViolations: int, cveViolations: int, reproViolations: int }
  var h: State
  action init = h' = { lockfilePinned: false, cveTombstoned: false, hermeticSandbox: false, twoBuilderMatch: false, admittedBuilds: 0, slopsquatViolations: 0, cveViolations: 0, reproViolations: 0 }
  action pinLockfileDeps = if (not(h.lockfilePinned)) h' = h.with("lockfilePinned", true) else h' = h
  action flagCveTombstone = if (not(h.cveTombstoned)) h' = h.with("cveTombstoned", true) else h' = h
  action enableHermeticSandbox = if (not(h.hermeticSandbox)) h' = h.with("hermeticSandbox", true) else h' = h
  action verifySecondBuilderParity = if (not(h.twoBuilderMatch)) h' = h.with("twoBuilderMatch", true) else h' = h
  action admitArtifactBuild = if ((h.admittedBuilds < 2 and h.lockfilePinned and not(h.cveTombstoned) and (h.hermeticSandbox and h.twoBuilderMatch))) h' = h.with("admittedBuilds", (h.admittedBuilds + 1)).with("slopsquatViolations", if (h.lockfilePinned) h.slopsquatViolations else (h.slopsquatViolations + 1)).with("cveViolations", if (not(h.cveTombstoned)) h.cveViolations else (h.cveViolations + 1)).with("reproViolations", if ((h.hermeticSandbox and h.twoBuilderMatch)) h.reproViolations else (h.reproViolations + 1)) else h' = h
  action step = any { pinLockfileDeps, flagCveTombstone, enableHermeticSandbox, verifySecondBuilderParity, admitArtifactBuild }
  val safety = (h.slopsquatViolations == 0 and h.cveViolations == 0 and h.reproViolations == 0)
  // Countermodel engineering.defense.supply-chain-provenance.slopsquatting (dropped guard: require-lockfile-pinned)
  action admitBuildSlopsquat = if ((h.admittedBuilds < 2 and true and not(h.cveTombstoned) and (h.hermeticSandbox and h.twoBuilderMatch))) h' = h.with("admittedBuilds", (h.admittedBuilds + 1)).with("slopsquatViolations", if (h.lockfilePinned) h.slopsquatViolations else (h.slopsquatViolations + 1)).with("cveViolations", if (not(h.cveTombstoned)) h.cveViolations else (h.cveViolations + 1)).with("reproViolations", if ((h.hermeticSandbox and h.twoBuilderMatch)) h.reproViolations else (h.reproViolations + 1)) else h' = h
  action stepSlopsquatting = any { step, admitBuildSlopsquat }
  // Countermodel engineering.defense.supply-chain-provenance.cve-tombstone (dropped guard: require-no-cve-tombstone)
  action admitBuildCve = if ((h.admittedBuilds < 2 and h.lockfilePinned and true and (h.hermeticSandbox and h.twoBuilderMatch))) h' = h.with("admittedBuilds", (h.admittedBuilds + 1)).with("slopsquatViolations", if (h.lockfilePinned) h.slopsquatViolations else (h.slopsquatViolations + 1)).with("cveViolations", if (not(h.cveTombstoned)) h.cveViolations else (h.cveViolations + 1)).with("reproViolations", if ((h.hermeticSandbox and h.twoBuilderMatch)) h.reproViolations else (h.reproViolations + 1)) else h' = h
  action stepCveTombstone = any { step, admitBuildCve }
  // Countermodel engineering.defense.supply-chain-provenance.non-reproducible (dropped guard: require-hermetic-reproducible)
  action admitBuildNonRepro = if ((h.admittedBuilds < 2 and h.lockfilePinned and not(h.cveTombstoned) and true)) h' = h.with("admittedBuilds", (h.admittedBuilds + 1)).with("slopsquatViolations", if (h.lockfilePinned) h.slopsquatViolations else (h.slopsquatViolations + 1)).with("cveViolations", if (not(h.cveTombstoned)) h.cveViolations else (h.cveViolations + 1)).with("reproViolations", if ((h.hermeticSandbox and h.twoBuilderMatch)) h.reproViolations else (h.reproViolations + 1)) else h' = h
  action stepNonReproducible = any { step, admitBuildNonRepro }
  run cleanSupplyChainTest = init.then(pinLockfileDeps).then(enableHermeticSandbox).then(verifySecondBuilderParity).then(admitArtifactBuild).then(all { assert(safety), assert(h.admittedBuilds == 1), h' = h })
  run slopsquattingViolatesSafetyTest = init.then(enableHermeticSandbox).then(verifySecondBuilderParity).then(admitBuildSlopsquat).then(all { assert(not(safety)), assert(h.slopsquatViolations > 0), h' = h })
  run cveTombstoneViolatesSafetyTest = init.then(pinLockfileDeps).then(flagCveTombstone).then(enableHermeticSandbox).then(verifySecondBuilderParity).then(admitBuildCve).then(all { assert(not(safety)), assert(h.cveViolations > 0), h' = h })
  run nonReproducibleViolatesSafetyTest = init.then(pinLockfileDeps).then(admitBuildNonRepro).then(all { assert(not(safety)), assert(h.reproViolations > 0), h' = h })
}
