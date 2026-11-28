;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Domain-owned state rollback model inheriting from EffectHandoffModel.
;;; Co-located Yuanxu unit: single source of truth alongside StateRollback.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/execution/effect-handoff/objects
                 EffectHandoffModel))
(export StateRollbackModel)

(.def (StateRollbackModel @ EffectHandoffModel)
  identity: 'threat.execution.state-rollback
  family: 'threat.execution.state-rollback
  title: "Monotonic Storage Guard & Host State-Rollback Replay"
  subdomain: 'quint.threat.execution
  papers:
  '(("B. Parno, J. R. Lorch, J. R. Douceur, J. Mickens & J. M. McCune (IEEE S&P 2011)"
     "Memoir: Practical State Continuity for Protected Modules — preventing host snapshot rollback attacks.")
    ("R. Strackx, B. Jacobs & F. Piessens (USENIX Security 2016)"
     "ICE: A Passive, High-Speed, State-Continuity Scheme for Trusted Execution Environments."))
  quint-module: "state_rollback"
  quint-file: "StateRollback.qnt"
  domain-dir: "threat/execution/state-rollback"
  rules:
  '((state-rollback-safe ROLL-SAFE quint)
    (state-rollback-countermodel ROLL-COUNTER quint))
  dependencies:
  '((ROLL-SAFE source)
    (ROLL-SAFE profile)
    (ROLL-SAFE method)
    (ROLL-COUNTER source)
    (ROLL-COUNTER profile)
    (ROLL-COUNTER method))
  invariant: "Monotonic storage prevents replaying a pre-handoff snapshot to emit a second effect."
  limits: "Finite rollback model; does not prove physical storage atomicity or external rail deduplication.")
