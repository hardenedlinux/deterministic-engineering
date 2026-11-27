;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Domain-owned guarded exact-effect handoff model (prepare / durable-commit / emit).
;;; Co-located Yuanxu unit: single source of truth alongside EffectHandoff.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export EffectHandoffModel)

(.def (EffectHandoffModel @ AuthorityCurrentnessModel)
  identity: 'threat.execution.effect-handoff
  family: 'threat.execution.effect-handoff
  title: "Guarded Exact-Effect Handoff (Prepare / Durable-Commit / Emit)"
  subdomain: 'quint.threat.execution
  papers:
  '(("J. Gray & L. Lamport (ACM TODS 2006)"
     "Consensus on Transaction Commit: prepare, durable commit acknowledgment, and uncertain outcomes.")
    ("P. Helland (CIDR 2007)"
     "Life Beyond Distributed Transactions: durable intent logging before external side-effect emission."))
  quint-module: "effect_handoff"
  quint-file: "EffectHandoff.qnt"
  domain-dir: "threat/execution/effect-handoff"
  rules:
  '((effect-handoff-once HAND-ONCE quint)
    (effect-handoff-no-durability HAND-NODUR quint))
  dependencies:
  '((HAND-ONCE source)
    (HAND-ONCE profile)
    (HAND-ONCE method)
    (HAND-NODUR source)
    (HAND-NODUR profile)
    (HAND-NODUR method))
  invariant: "Prepared effects commit durably under current authority and emit at most MaxSends times while retaining unknown outcomes."
  limits: "Finite protocol abstraction; trusted bits summarize native interpreters; no cryptography, real CAS, codec correctness or Lean refinement is claimed.")
