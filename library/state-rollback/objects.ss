;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Domain-owned state rollback model inheriting from EffectHandoffModel.
;;; Emergent safety (zero synthetic unsafe flag) + typed structural AST.
(import :clan/poo/object
        (only-in "../effect-handoff/objects.ss" EffectHandoffModel NoDurabilityCountermodel))
(export StateRollbackModel RollbackCountermodel)

(.def (StateRollbackModel @ EffectHandoffModel)
  identity: 'threat.state-rollback
  family: 'threat.state-rollback
  quint-module: "state_rollback"
  quint-file: "StateRollback.qnt"
  domain-dir: "threat/state-rollback"
  rules: '((state-rollback-safe ROLL-SAFE quint)
           (state-rollback-countermodel ROLL-COUNTER quint))
  dependencies: '((ROLL-SAFE source) (ROLL-SAFE profile) (ROLL-SAFE method)
                  (ROLL-COUNTER source) (ROLL-COUNTER profile) (ROLL-COUNTER method))
  invariant: "Monotonic storage prevents replaying a pre-handoff snapshot to emit a second effect."
  guards: => (cut append <> '((monotonic-storage (<= (. h sent) MaxSends))))
  traces: => (cut append <>
                  '((rollbackCountermodelTest
                     (run rollbackCountermodelTest
                       (then init prepare (call commitAs #t) emit replayOldState unsafe)))))
  countermodels: (list NoDurabilityCountermodel RollbackCountermodel)
  limits: "Finite rollback model; does not prove physical storage atomicity or external rail deduplication.")

;; Weakened descendant: allows host snapshot rollback after emission; must violate safety (sent > MaxSends).
(.def (RollbackCountermodel @ StateRollbackModel)
  identity: 'threat.state-rollback.replay-old-state
  dropped-guard: 'monotonic-storage
  step-action: "stepRollback"
  counter-action:
  '(decls
     (action replayOldState ()
       (if (= (. h phase) 3)
         (set-h (sent (+ (. h sent) 1)))
         (keep-h)))
     (action stepRollback () (any step replayOldState)))
  expected-itf-predicate: "h.sent >= 2")
