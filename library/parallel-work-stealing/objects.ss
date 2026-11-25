;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Chase-Lev work-stealing deque protocol abstraction with last-item CAS arbitration
;;; and weakened countermodel omitting last-item CAS (double-taking the final task).
(import :clan/poo/object
        (only-in "../threat-capabilities/objects.ss" ThreatModel.))
(export WorkStealingDequeModel MissingLastItemCasCountermodel)

(.def (WorkStealingDequeModel @ ThreatModel.)
  identity: 'engineering.parallel.work-stealing-deque
  family: 'engineering.parallel.work-stealing-deque
  quint-module: "parallel_work_stealing"
  quint-file: "WorkStealingDeque.qnt"
  domain-dir: "engineering/parallel/work-stealing-deque"
  quint-imports: '()
  rules: '((par-ws-once PAR-WS-ONCE quint)
           (par-ws-no-cas PAR-WS-NOCAS quint))
  dependencies: '((PAR-WS-ONCE source) (PAR-WS-ONCE profile) (PAR-WS-ONCE method)
                  (PAR-WS-NOCAS source) (PAR-WS-NOCAS profile) (PAR-WS-NOCAS method))
  invariant: "Every pushed task is taken at most once across concurrent owner pop and thief steal operations."
  parameters: '()
  state: '((top "int" "0")
           (bottom "int" "0")
           (pushed "int" "0")
           (ownerPopped "int" "0")
           (thiefStolen "int" "0")
           (doubleTaken "bool" "false"))
  guards: '((last-item-cas "ownerPop and thiefSteal arbitrate single remaining task atomically"))
  transitions:
  '((dequeLen "val dequeLen = h.bottom - h.top")
    (ownerPush "action ownerPush = if (h.pushed < 3)\n    h' = h.with(\"bottom\", h.bottom + 1).with(\"pushed\", h.pushed + 1)\n    else h' = h")
    (ownerPop "action ownerPop = if (h.bottom > h.top)\n    h' = h.with(\"bottom\", h.bottom - 1).with(\"ownerPopped\", h.ownerPopped + 1)\n    else h' = h")
    (thiefSteal "action thiefSteal = if (h.top < h.bottom)\n    h' = h.with(\"top\", h.top + 1).with(\"thiefStolen\", h.thiefStolen + 1)\n    else h' = h")
    (step "action step = any { ownerPush, ownerPop, thiefSteal }"))
  safety: "not(h.doubleTaken) and h.ownerPopped + h.thiefStolen <= h.pushed and h.top <= h.bottom"
  traces:
  '((checkSafe "action checkSafe = all { assert(safety), h' = h }")
    (checkDouble "action checkDouble = all { assert(h.doubleTaken), assert(not(safety)), h' = h }")
    (pushPopTest "run pushPopTest = init.then(ownerPush).then(ownerPop).then(all { assert(h.ownerPopped == 1), assert(safety), h' = h })")
    (pushStealTest "run pushStealTest = init.then(ownerPush).then(thiefSteal).then(ownerPop).then(all { assert(h.thiefStolen == 1), assert(h.ownerPopped == 0), assert(safety), h' = h })")
    (missingCasDoubleTakeTest "run missingCasDoubleTakeTest = init.then(ownerPush).then(raceLastItemNoCas).then(checkDouble)"))
  countermodels: (list MissingLastItemCasCountermodel)
  limits: "Finite 1-owner/1-thief Chase-Lev deque abstraction; does not model circular array resizing or ARMv8/TSO weak memory fences.")

;; Weakened descendant: owner pop and thief steal both consume the sole remaining item without CAS.
(.def (MissingLastItemCasCountermodel @ WorkStealingDequeModel)
  identity: 'engineering.parallel.work-stealing-deque.missing-last-item-cas
  dropped-guard: 'last-item-cas
  step-action: "stepNoLastItemCas"
  counter-action: "action raceLastItemNoCas = if (h.bottom - h.top == 1)\n    h' = h.with(\"top\", h.top + 1).with(\"bottom\", h.bottom - 1).with(\"ownerPopped\", h.ownerPopped + 1).with(\"thiefStolen\", h.thiefStolen + 1).with(\"doubleTaken\", true)\n    else h' = h\n  action stepNoLastItemCas = any { step, raceLastItemNoCas }"
  expected-itf-predicate: "h.doubleTaken == true and h.ownerPopped + h.thiefStolen > h.pushed")
