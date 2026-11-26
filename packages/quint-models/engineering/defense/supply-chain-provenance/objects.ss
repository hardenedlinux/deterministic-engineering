;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Business Extension B14 (10.187 / 10.188): Hermetic Supply-Chain & Reproducible
;;; Build Provenance (SLSA / in-toto, Anti-Slopsquatting Lockfile Pinning,
;;; CVE Tombstones & 2-Builder Bit-for-Bit Parity).
;;; Proves three artifact-admission safety invariants:
;;;   1. Anti-Slopsquatting: every dependency is pinned in the signed M1 lockfile
;;;      (slopsquatViolations == 0).
;;;   2. CVE Tombstone Blocking: no CVE-tombstoned dependency can enter a release
;;;      build (cveViolations == 0).
;;;   3. Hermetic 2-Builder Reproducibility: builds must be network-isolated and
;;;      bit-for-bit matched by an independent second builder (reproViolations == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export SupplyChainProvenanceModel
        SlopsquattingCountermodel
        CveTombstoneCountermodel
        NonReproducibleCountermodel)

(.def (SupplyChainProvenanceModel @ ThreatModel.)
  identity: 'engineering.defense.supply-chain-provenance
  family: 'engineering.defense.supply-chain-provenance
  title: "Hermetic Supply-Chain & Reproducible Build Provenance"
  subdomain: 'quint.engineering.defense
  papers:
  '(("K. Thompson (Turing Award Lecture, CACM 1984)"
     "Reflections on Trusting Trust — defending against compiler/builder backdoors via independent reproduction.")
    ("SLSA & in-toto Frameworks (CNCF / OpenSSF)"
     "Hermetic signed build provenance binding source, toolchain, SBOM, and output digests.")
    ("Deterministic Engineering (10.187 / 10.188)"
     "Anti-slopsquatting M1 lockfile pinning, CVE tombstones, and 2-builder reproducible build gates."))
  quint-module: "supply_chain_provenance"
  quint-file: "SupplyChainProvenance.qnt"
  domain-dir: "engineering/defense/supply-chain-provenance"
  verify-depth: 10
  countermodel-depth: 6
  rules:
  '((supply-chain-safe DE-SCP-SAFE quint)
    (supply-chain-countermodel DE-SCP-COUNTER quint))
  dependencies:
  '((DE-SCP-SAFE source)
    (DE-SCP-SAFE profile)
    (DE-SCP-SAFE method)
    (DE-SCP-COUNTER source)
    (DE-SCP-COUNTER profile)
    (DE-SCP-COUNTER method))
  invariant: "Artifact build admission requires signed lockfile pinning (slopsquatViolations == 0), zero CVE tombstones (cveViolations == 0), and hermetic 2-builder parity (reproViolations == 0)."
  parameters: '()
  state:
  '((lockfilePinned "bool" "false")
    (cveTombstoned "bool" "false")
    (hermeticSandbox "bool" "false")
    (twoBuilderMatch "bool" "false")
    (admittedBuilds "int" "0")
    (slopsquatViolations "int" "0")
    (cveViolations "int" "0")
    (reproViolations "int" "0"))
  guards:
  '((require-lockfile-pinned (. h lockfilePinned))
    (require-no-cve-tombstone (not (. h cveTombstoned)))
    (require-hermetic-reproducible (and (. h hermeticSandbox) (. h twoBuilderMatch))))
  transitions:
  '((pinLockfileDeps
      (action pinLockfileDeps ()
        (if (not (. h lockfilePinned))
          (set-h (lockfilePinned #t))
          (keep-h))))
    (flagCveTombstone
      (action flagCveTombstone ()
        (if (not (. h cveTombstoned))
          (set-h (cveTombstoned #t))
          (keep-h))))
    (enableHermeticSandbox
      (action enableHermeticSandbox ()
        (if (not (. h hermeticSandbox))
          (set-h (hermeticSandbox #t))
          (keep-h))))
    (verifySecondBuilderParity
      (action verifySecondBuilderParity ()
        (if (not (. h twoBuilderMatch))
          (set-h (twoBuilderMatch #t))
          (keep-h))))
    (admitArtifactBuild
      (action admitArtifactBuild ()
        (if (and (< (. h admittedBuilds) 2)
                 (guard require-lockfile-pinned (. h lockfilePinned))
                 (guard require-no-cve-tombstone (not (. h cveTombstoned)))
                 (guard require-hermetic-reproducible (and (. h hermeticSandbox) (. h twoBuilderMatch))))
          (set-h (admittedBuilds (+ (. h admittedBuilds) 1))
                 (slopsquatViolations
                   (if (. h lockfilePinned)
                     (. h slopsquatViolations)
                     (+ (. h slopsquatViolations) 1)))
                 (cveViolations
                   (if (not (. h cveTombstoned))
                     (. h cveViolations)
                     (+ (. h cveViolations) 1)))
                 (reproViolations
                   (if (and (. h hermeticSandbox) (. h twoBuilderMatch))
                     (. h reproViolations)
                     (+ (. h reproViolations) 1))))
          (keep-h))))
    (step
      (action step ()
        (any pinLockfileDeps flagCveTombstone enableHermeticSandbox
             verifySecondBuilderParity admitArtifactBuild))))
  safety:
  '(and (= (. h slopsquatViolations) 0)
        (= (. h cveViolations) 0)
        (= (. h reproViolations) 0))
  traces:
  '((cleanSupplyChainTest
      (run cleanSupplyChainTest
        (then init pinLockfileDeps enableHermeticSandbox verifySecondBuilderParity admitArtifactBuild
              (all (assert safety)
                   (assert (= (. h admittedBuilds) 1))
                   (keep-h)))))
    (slopsquattingViolatesSafetyTest
      (run slopsquattingViolatesSafetyTest
        (then init enableHermeticSandbox verifySecondBuilderParity admitBuildSlopsquat
              (all (assert (not safety))
                   (assert (> (. h slopsquatViolations) 0))
                   (keep-h)))))
    (cveTombstoneViolatesSafetyTest
      (run cveTombstoneViolatesSafetyTest
        (then init pinLockfileDeps flagCveTombstone enableHermeticSandbox verifySecondBuilderParity admitBuildCve
              (all (assert (not safety))
                   (assert (> (. h cveViolations) 0))
                   (keep-h)))))
    (nonReproducibleViolatesSafetyTest
      (run nonReproducibleViolatesSafetyTest
        (then init pinLockfileDeps admitBuildNonRepro
              (all (assert (not safety))
                   (assert (> (. h reproViolations) 0))
                   (keep-h))))))
  countermodels:
  (list SlopsquattingCountermodel
        CveTombstoneCountermodel
        NonReproducibleCountermodel)
  limits: "Bounded 2-build abstraction over lockfile pinning, CVE tombstones, and hermetic 2-builder parity; unbounded SBOM dependency lists and builder signatures are proved in SupplyChainProvenance.lean.")

(.def (SlopsquattingCountermodel @ SupplyChainProvenanceModel)
  identity: 'engineering.defense.supply-chain-provenance.slopsquatting
  dropped-guard: 'require-lockfile-pinned
  step-action: "stepSlopsquatting"
  derive-from-transition: 'admitArtifactBuild
  derive-action-name: 'admitBuildSlopsquat
  expected-itf-predicate: "h.slopsquatViolations > 0")

(.def (CveTombstoneCountermodel @ SupplyChainProvenanceModel)
  identity: 'engineering.defense.supply-chain-provenance.cve-tombstone
  dropped-guard: 'require-no-cve-tombstone
  step-action: "stepCveTombstone"
  derive-from-transition: 'admitArtifactBuild
  derive-action-name: 'admitBuildCve
  expected-itf-predicate: "h.cveViolations > 0")

(.def (NonReproducibleCountermodel @ SupplyChainProvenanceModel)
  identity: 'engineering.defense.supply-chain-provenance.non-reproducible
  dropped-guard: 'require-hermetic-reproducible
  step-action: "stepNonReproducible"
  derive-from-transition: 'admitArtifactBuild
  derive-action-name: 'admitBuildNonRepro
  expected-itf-predicate: "h.reproViolations > 0")
