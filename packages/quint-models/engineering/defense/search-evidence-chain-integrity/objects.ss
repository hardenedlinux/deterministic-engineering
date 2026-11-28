;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Scenario B Search Evidence-Chain Integrity, Structural vs Comment Drift,
;;; Negative-Domain Expansion (DE01), KV-Cache Epoch Fencing, and ATMS Poison Retraction.
;;;
;;; Unifies Marlin's downstream Scenario B search (Dusa finite-choice disambiguation
;;; + architecture constraint solving + ASCENT evidence accumulation) with upstream
;;; Deterministic Engineering defense invariants:
;;;   1. Unverified M2 LLM search claims or tombstoned poisoned claims can never be
;;;      promoted into M1 verified search evidence (poisonedPromotionViolations == 0).
;;;   2. Comment-only edits preserve M1 structural evidence reuse, whereas AST
;;;      structural drift invalidates stale structural evidence until reconciled
;;;      (staleStructuralReuseViolations == 0).
;;;   3. Expanding a watched negative scope (DE01) immediately invalidates universal/
;;;      negative search claims over that domain (staleNegDomainReuseViolations == 0).
;;;   4. KV-cached prompt/context conclusions must match the active structural epoch,
;;;      retain pinned constraints, and exclude retracted claims
;;;      (kvCacheContaminationViolations == 0).
;;;   5. Retracting a poisoned or drifted root invalidates single-support derived
;;;      chains while preserving ATMS chains backed by an independent clean support
;;;      (zombieCascadeViolations == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export SearchEvidenceChainIntegrityModel)

(.def (SearchEvidenceChainIntegrityModel @ ThreatModel.)
  identity: 'engineering.defense.search-evidence-chain-integrity
  family: 'engineering.defense.search-evidence-chain-integrity
  title: "Scenario B Search Evidence-Chain Integrity: Structural Drift, KV-Cache Fencing & ATMS Poison Retraction"
  subdomain: 'quint.engineering.defense
  papers:
  '(("J. Doyle (Artificial Intelligence 1979) / J. de Kleer (AIJ 1986)"
     "TMS & ATMS causal justification graphs and multi-support belief revision.")
    ("C. Martens, R. Simmons, M. Arntzenius (POPL 2025)"
     "Dusa: Finite-Choice Logic Programming with deduction vs branch provenance.")
    ("Deterministic Engineering (10.165 / 20.17 / Marlin Scenario B)"
     "Bi-temporal search evidence chains with structural vs comment fingerprinting, DE01 negative-domain revalidation, KV-cache epoch fencing, and ATMS poison tombstones."))
  quint-module: "search_evidence_chain_integrity"
  quint-file: "SearchEvidenceChainIntegrity.qnt"
  domain-dir: "engineering/defense/search-evidence-chain-integrity"
  rules:
  '((search-evidence-chain-safe DE-SECI-SAFE quint)
    (search-evidence-chain-countermodel DE-SECI-COUNTER quint))
  dependencies:
  '((DE-SECI-SAFE source)
    (DE-SECI-SAFE profile)
    (DE-SECI-SAFE method)
    (DE-SECI-COUNTER source)
    (DE-SECI-COUNTER profile)
    (DE-SECI-COUNTER method))
  invariant: "No stale structural evidence is reused after AST drift, no negative-scope claim is reused after domain expansion, no stale or unpinned KV-cached conclusion is served, no unverified or tombstoned claim enters M1 evidence, and no zombie derived chain is consumed after sole-support retraction."
  limits: "Finite single-root/single-derived Scenario B evidence-chain abstraction over comment vs structural AST drift, DE01 negative-domain expansion, KV-cache epoch/pin fencing, and ATMS multi-justification retraction; unbounded multi-file dependency graphs and cryptographic SHA-256 receipts are verified in Marlin's executable ASCENT/Dusa truth-maintenance suite.")
