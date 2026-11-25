;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Structured concurrency cancellation & child-drain quiescence model.
;;; Models parent scope cancellation waiting for all child tasks to drain before exit,
;;; paired with a fire-and-forget exit countermodel producing orphaned side effects.
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
  guards: '((child-quiescence-barrier "h.c1State != 1 and h.c1State != 2 and h.c2State != 1 and h.c2State != 2"))
  transitions:
  '((childrenQuiescent "val childrenQuiescent = h.c1State != 1 and h.c1State != 2 and h.c2State != 1 and h.c2State != 2")
    (spawnC1 "action spawnC1 = if (not(h.parentExited) and not(h.cancelRequested) and h.c1State == 0)\n    h' = h.with(\"c1State\", 1)\n    else h' = h")
    (spawnC2 "action spawnC2 = if (not(h.parentExited) and not(h.cancelRequested) and h.c2State == 0)\n    h' = h.with(\"c2State\", 1)\n    else h' = h")
    (requestCancel "action requestCancel = if (not(h.parentExited) and not(h.cancelRequested))\n    h' = h.with(\"cancelRequested\", true)\n    else h' = h")
    (c1Drain "action c1Drain = if (h.c1State == 1 and h.cancelRequested)\n    h' = h.with(\"c1State\", 2)\n    else h' = h")
    (c2Drain "action c2Drain = if (h.c2State == 1 and h.cancelRequested)\n    h' = h.with(\"c2State\", 2)\n    else h' = h")
    (c1Complete "action c1Complete = if (h.c1State == 1 or h.c1State == 2)\n    h' = h.with(\"c1State\", 3).with(\"orphanEffect\", h.orphanEffect or h.parentExited)\n    else h' = h")
    (c2Complete "action c2Complete = if (h.c2State == 1 or h.c2State == 2)\n    h' = h.with(\"c2State\", 3).with(\"orphanEffect\", h.orphanEffect or h.parentExited)\n    else h' = h")
    (parentExit "action parentExit = if (not(h.parentExited) and h.cancelRequested and childrenQuiescent)\n    h' = h.with(\"parentExited\", true)\n    else h' = h")
    (step "action step = any { spawnC1, spawnC2, requestCancel, c1Drain, c2Drain, c1Complete, c2Complete, parentExit }"))
  safety: "not(h.orphanEffect) and (not(h.parentExited) or childrenQuiescent)"
  traces:
  '((checkSafeExit "action checkSafeExit = all { assert(h.parentExited), assert(safety), h' = h }")
    (checkOrphan "action checkOrphan = all { assert(h.orphanEffect), assert(not(safety)), h' = h }")
    (gracefulDrainExitTest "run gracefulDrainExitTest = init.then(spawnC1).then(requestCancel).then(c1Drain).then(c1Complete).then(parentExit).then(checkSafeExit)")
    (activeChildBlocksExitTest "run activeChildBlocksExitTest = init.then(spawnC1).then(requestCancel).then(parentExit).then(all { assert(not(h.parentExited)), assert(safety), h' = h })")
    (fireAndForgetOrphanTest "run fireAndForgetOrphanTest = init.then(spawnC1).then(requestCancel).then(parentExitUnchecked).then(c1Complete).then(checkOrphan)"))
  countermodels: (list FireAndForgetExitCountermodel)
  limits: "Finite 2-child structured concurrency abstraction; does not model OS thread scheduling, panic unwinding, or non-cooperative blocking I/O.")

;; Weakened descendant: parent exits on cancel without waiting for children to drain.
(.def (FireAndForgetExitCountermodel @ StructuredCancelModel)
  identity: 'engineering.concurrency.structured-cancellation.fire-and-forget-exit
  dropped-guard: 'child-quiescence-barrier
  step-action: "stepFireAndForgetExit"
  counter-action: "action parentExitUnchecked = if (not(h.parentExited) and h.cancelRequested)\n    h' = h.with(\"parentExited\", true)\n    else h' = h\n  action stepFireAndForgetExit = any { step, parentExitUnchecked }"
  expected-itf-predicate: "h.parentExited == true and (h.c1State == 1 or h.c2State == 1)")
