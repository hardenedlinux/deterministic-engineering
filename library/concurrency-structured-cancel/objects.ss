;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Structured concurrency cancellation & child-drain quiescence model.
;;; Typed structural AST + auto-derived fire-and-forget countermodel via (guard ...).
(import :clan/poo/object
        (only-in "../threat-capabilities/objects.ss" ThreatModel.))
(export StructuredCancelModel FireAndForgetExitCountermodel)

(.def (StructuredCancelModel @ ThreatModel.)
  identity: 'engineering.concurrency.structured-cancellation
  family: 'engineering.concurrency.structured-cancellation
  quint-module: "concurrency_structured_cancel"
  quint-file: "StructuredCancellation.qnt"
  domain-dir: "engineering/concurrency/structured-cancellation"
  quint-imports: '()
  rules: '((conc-cancel-quiescent CONC-CANCEL-QUIES quint)
           (conc-cancel-orphan CONC-CANCEL-ORPHAN quint))
  dependencies: '((CONC-CANCEL-QUIES source) (CONC-CANCEL-QUIES profile) (CONC-CANCEL-QUIES method)
                  (CONC-CANCEL-ORPHAN source) (CONC-CANCEL-ORPHAN profile) (CONC-CANCEL-ORPHAN method))
  invariant: "Parent scope exits only after every spawned child task completes draining, preventing orphaned effects after scope close."
  parameters: '()
  ;; Child states: 0=Idle, 1=Running, 2=Draining, 3=Done.
  state: '((cancelRequested "bool" "false")
           (parentExited "bool" "false")
           (c1State "int" "0")
           (c2State "int" "0")
           (orphanEffect "bool" "false"))
  guards: '((child-quiescence-barrier (and (!= (. h c1State) 1) (!= (. h c1State) 2)
                                           (!= (. h c2State) 1) (!= (. h c2State) 2))))
  transitions:
  '((childrenQuiescent
     (val childrenQuiescent
       (and (!= (. h c1State) 1) (!= (. h c1State) 2)
            (!= (. h c2State) 1) (!= (. h c2State) 2))))
    (spawnC1
     (action spawnC1 ()
       (if (and (not (. h parentExited)) (not (. h cancelRequested)) (= (. h c1State) 0))
         (set-h (c1State 1))
         (keep-h))))
    (spawnC2
     (action spawnC2 ()
       (if (and (not (. h parentExited)) (not (. h cancelRequested)) (= (. h c2State) 0))
         (set-h (c2State 1))
         (keep-h))))
    (requestCancel
     (action requestCancel ()
       (if (and (not (. h parentExited)) (not (. h cancelRequested)))
         (set-h (cancelRequested #t))
         (keep-h))))
    (c1Drain
     (action c1Drain ()
       (if (and (= (. h c1State) 1) (. h cancelRequested))
         (set-h (c1State 2))
         (keep-h))))
    (c2Drain
     (action c2Drain ()
       (if (and (= (. h c2State) 1) (. h cancelRequested))
         (set-h (c2State 2))
         (keep-h))))
    (c1Complete
     (action c1Complete ()
       (if (or (= (. h c1State) 1) (= (. h c1State) 2))
         (set-h (c1State 3) (orphanEffect (or (. h orphanEffect) (. h parentExited))))
         (keep-h))))
    (c2Complete
     (action c2Complete ()
       (if (or (= (. h c2State) 1) (= (. h c2State) 2))
         (set-h (c2State 3) (orphanEffect (or (. h orphanEffect) (. h parentExited))))
         (keep-h))))
    (parentExit
     (action parentExit ()
       (if (and (not (. h parentExited))
                (. h cancelRequested)
                (guard child-quiescence-barrier childrenQuiescent))
         (set-h (parentExited #t))
         (keep-h))))
    (step
     (action step ()
       (any spawnC1 spawnC2 requestCancel c1Drain c2Drain c1Complete c2Complete parentExit))))
  safety:
  '(and (not (. h orphanEffect))
        (or (not (. h parentExited)) childrenQuiescent))
  traces:
  '((checkSafeExit (action checkSafeExit () (all (assert (. h parentExited)) (assert safety) (keep-h))))
    (checkOrphan (action checkOrphan () (all (assert (. h orphanEffect)) (assert (not safety)) (keep-h))))
    (gracefulDrainExitTest
     (run gracefulDrainExitTest
       (then init spawnC1 requestCancel c1Drain c1Complete parentExit checkSafeExit)))
    (activeChildBlocksExitTest
     (run activeChildBlocksExitTest
       (then init spawnC1 requestCancel parentExit
             (all (assert (not (. h parentExited))) (assert safety) (keep-h)))))
    (fireAndForgetOrphanTest
     (run fireAndForgetOrphanTest
       (then init spawnC1 requestCancel parentExitUnchecked c1Complete checkOrphan))))
  countermodels: (list FireAndForgetExitCountermodel)
  limits: "Finite 2-child structured concurrency abstraction; does not model OS thread scheduling, panic unwinding, or non-cooperative blocking I/O.")

;; Weakened descendant: parent exits on cancel without waiting for children to drain.
(.def (FireAndForgetExitCountermodel @ StructuredCancelModel)
  identity: 'engineering.concurrency.structured-cancellation.fire-and-forget-exit
  dropped-guard: 'child-quiescence-barrier
  step-action: "stepFireAndForgetExit"
  derive-from-transition: 'parentExit
  derive-action-name: 'parentExitUnchecked
  expected-itf-predicate: "h.parentExited == true and (h.c1State == 1 or h.c2State == 1)")
