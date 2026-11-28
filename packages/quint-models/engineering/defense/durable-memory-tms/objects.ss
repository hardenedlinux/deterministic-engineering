;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Business Extension B8 (10.165): Durable Memory-Poisoning Defense,
;;; Independent Quorum Fact Promotion, and Doyle/ATMS Causal Belief Retraction.
;;; Proves three long-horizon durable AI memory safety invariants:
;;;   1. Unverified/untrusted claims stay quarantined in M2 provisional memory
;;;      and can never enter M1 verified memory (poisonedPromotionViolations == 0).
;;;   2. Retracted poisoned claims are permanently immunized against re-ingestion
;;;      (repoisoningViolations == 0).
;;;   3. Causal TMS retraction invalidates single-support derived beliefs while
;;;      preserving ATMS beliefs backed by an independent clean justification
;;;      (zombieDerivedViolations == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export DurableMemoryTmsModel)

(.def (DurableMemoryTmsModel @ ThreatModel.)
  identity: 'engineering.defense.durable-memory-tms
  family: 'engineering.defense.durable-memory-tms
  title: "Durable Memory-Poisoning Defense: Quorum Promotion & ATMS Causal Retraction"
  subdomain: 'quint.engineering.defense
  papers:
  '(("J. Doyle (Artificial Intelligence 1979) / J. de Kleer (AIJ 1986)"
     "A Truth Maintenance System (TMS) & Assumption-Based TMS (ATMS): causal justification graphs and multi-support belief revision.")
    ("D. Malkhi & M. Reiter (Distributed Computing 1998)"
     "Byzantine Quorum Systems for independent multi-witness fact attestation.")
    ("Deterministic Engineering (10.156 / 10.165)"
     "Two-tier M2 provisional vs. M1 verified durable AI memory with causal retraction and poison-immunization tombstones."))
  quint-module: "durable_memory_tms"
  quint-file: "DurableMemoryTms.qnt"
  domain-dir: "engineering/defense/durable-memory-tms"
  rules:
  '((durable-memory-tms-safe DE-TMS-SAFE quint)
    (durable-memory-tms-countermodel DE-TMS-COUNTER quint))
  dependencies:
  '((DE-TMS-SAFE source)
    (DE-TMS-SAFE profile)
    (DE-TMS-SAFE method)
    (DE-TMS-COUNTER source)
    (DE-TMS-COUNTER profile)
    (DE-TMS-COUNTER method))
  invariant: "No unverified or untrusted claim enters M1 verified memory (poisonedPromotionViolations == 0), no retracted poisoned claim is re-ingested (repoisoningViolations == 0), and no derived belief lacking a surviving clean justification is read after root retraction (zombieDerivedViolations == 0)."
  limits: "Finite single-root and single-derived ATMS belief revision abstraction; does not model probabilistic confidence calibration, contradictory belief resolution over cycles, or natural-language semantic equivalence beyond canonical claim digests.")
