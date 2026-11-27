;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Business Extension B12 (10.184 / 10.186): Controlled Context Distillation &
;;; Epistemic Provenance Preservation.
;;; Proves three context-compaction safety invariants:
;;;   1. Anti-Amnesia: every pinned M1 negative constraint/veto is retained
;;;      verbatim during distillation (amnesiaViolations == 0).
;;;   2. Anti-Integrity-Laundering: untrusted external inputs cannot be elevated
;;;      to trusted integrity during summarization (launderingViolations == 0).
;;;   3. Anti-Secrecy-Stripping: paraphrasing never strips DIFC secrecy tags
;;;      without an audited M3 declassification (secrecyStripViolations == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export ContextDistillationProvenanceModel)

(.def (ContextDistillationProvenanceModel @ ThreatModel.)
  identity: 'engineering.defense.context-distillation-provenance
  family: 'engineering.defense.context-distillation-provenance
  title: "Controlled Context Distillation & Epistemic Provenance Preservation"
  subdomain: 'quint.engineering.defense
  papers:
  '(("E. Debenedetti et al. (2025)"
     "CaMeL: Defeating Prompt Injections by Design — monotonic integrity lattice across LLM synthesis.")
    ("A. C. Myers & B. Liskov (SOSP 1997 / ACM TOSEM 2000)"
     "Decentralized Information Flow Control (DIFC) — no silent secrecy tag removal without declassification.")
    ("Deterministic Engineering (10.184 / 10.186)"
     "Anti-amnesia M1 constraint retention, grounded citations, and provenance-preserving context compaction."))
  quint-module: "context_distillation_provenance"
  quint-file: "ContextDistillationProvenance.qnt"
  domain-dir: "engineering/defense/context-distillation-provenance"
  rules:
  '((context-distillation-safe DE-CDP-SAFE quint)
    (context-distillation-countermodel DE-CDP-COUNTER quint))
  dependencies:
  '((DE-CDP-SAFE source)
    (DE-CDP-SAFE profile)
    (DE-CDP-SAFE method)
    (DE-CDP-COUNTER source)
    (DE-CDP-COUNTER profile)
    (DE-CDP-COUNTER method))
  invariant: "Context distillation retains all pinned M1 constraints (amnesiaViolations == 0), never elevates untrusted external integrity (launderingViolations == 0), and preserves all secret tags without M3 declassification (secrecyStripViolations == 0)."
  limits: "Bounded 2-distillation abstraction over pinned constraint retention, integrity meet, and secrecy propagation; unbounded multi-item DAG and citation grounding are proved in ContextDistillationAndProvenance.lean.")
