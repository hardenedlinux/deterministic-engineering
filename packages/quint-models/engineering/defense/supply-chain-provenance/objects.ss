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
(export SupplyChainProvenanceModel)

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
  limits: "Bounded 2-build abstraction over lockfile pinning, CVE tombstones, and hermetic 2-builder parity; unbounded SBOM dependency lists and builder signatures are proved in SupplyChainProvenance.lean.")
