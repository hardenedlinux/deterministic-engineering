;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Durable AI (10.157): Role-Projected Context (Truth vs View), Compaction-Loss-Free
;;; Evidence Offloading (Anti-Overthinking), Multi-Agent ReadSet x WriteSet SSI Write-Skew
;;; Prevention, and Monotonic M3 Lease Fencing for Stalled Workers.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export DurableAiContextSsiModel)

(.def (DurableAiContextSsiModel @ ThreatModel.)
  identity: 'engineering.defense.durable-ai-context-ssi
  family: 'engineering.defense.durable-ai-context-ssi
  title: "Durable AI Role-Projected Context & Multi-Agent SSI Write-Skew Governance"
  subdomain: 'quint.engineering.defense
  papers:
  '(("M. J. Cahill, U. Rohm & A. D. Fekete (SIGMOD 2008 / ACM TODS 2009)"
     "Serializable Isolation for Snapshot Databases: rw-antidependency detection against Write-Skew.")
    ("Mighty Gerbils (gerbil-persist) & Deterministic Engineering (10.156 / 10.157)"
     "Durable Merkle Evidence State as Truth, Role-Projected Context as Ephemeral Materialized View, and Anti-Overthinking Sufficiency Offloading."))
  quint-module: "durable_ai_context_ssi"
  quint-file: "DurableAiContextSsi.qnt"
  domain-dir: "engineering/defense/durable-ai-context-ssi"
  rules:
  '((durable-ai-safe DE-DAI-SAFE quint)
    (durable-ai-countermodel DE-DAI-COUNTER quint))
  dependencies:
  '((DE-DAI-SAFE source)
    (DE-DAI-SAFE profile)
    (DE-DAI-SAFE method)
    (DE-DAI-COUNTER source)
    (DE-DAI-COUNTER profile)
    (DE-DAI-COUNTER method))
  invariant: "Durable Merkle evidence survives raw chat compaction (durableEvidenceIntact), no disjoint-file rw-antidependency merges blindly (writeSkewMerges == 0), no stalled worker with outdated fencing epoch commits (fencedCommits == 0), and no reviewer context carries unsanitized coder prose injection (injectedReviews == 0)."
  limits: "Finite two-agent SSI rw-antidependency, two-epoch lease fencing, and reviewer context sanitization abstraction; does not model arbitrary multi-hop transitive dependency graphs or covert steganography inside valid code diffs.")
