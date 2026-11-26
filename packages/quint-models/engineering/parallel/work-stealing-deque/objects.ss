;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Chase-Lev work-stealing deque protocol abstraction with two-step thief read + CAS arbitration.
;;; Co-located Yuanxu unit: single source of truth alongside WorkStealingDeque.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export WorkStealingDequeModel
        MissingLastItemCasCountermodel)

(.def (WorkStealingDequeModel @ ThreatModel.)
  identity: 'engineering.parallel.work-stealing-deque
  family: 'engineering.parallel.work-stealing-deque
  title: "Chase-Lev Work-Stealing Deque & Last-Item CAS Arbitration"
  subdomain: 'quint.engineering.parallel
  papers:
  '(("D. Chase & Y. Lev (ACM SPAA 2005)"
     "Dynamic Circular Work-Stealing Deque: owner pop vs. thief steal CAS arbitration on the final element.")
    ("N. M. Lê, A. Pop, A. Cohen & F. Zappa Nardelli (ACM PPoPP 2013)"
     "Correct and Efficient Work-Stealing for Weak Memory Models."))
  quint-module: "parallel_work_stealing"
  quint-file: "WorkStealingDeque.qnt"
  domain-dir: "engineering/parallel/work-stealing-deque"
  quint-imports: '()
  rules:
  '((par-ws-once PAR-WS-ONCE quint)
    (par-ws-no-cas PAR-WS-NOCAS quint))
  dependencies:
  '((PAR-WS-ONCE source)
    (PAR-WS-ONCE profile)
    (PAR-WS-ONCE method)
    (PAR-WS-NOCAS source)
    (PAR-WS-NOCAS profile)
    (PAR-WS-NOCAS method))
  invariant: "Every pushed task is taken at most once across concurrent owner pop and thief steal operations."
  parameters: '()
  state:
  '((top "int" "0")
    (bottom "int" "0")
    (pushed "int" "0")
    (ownerPopped "int" "0")
    (thiefStolen "int" "0")
    (thiefReadTop "int" "-1"))
  guards:
  '((last-item-cas
      (and (= (. h top) (. h thiefReadTop))
           (< (. h top) (. h bottom)))))
  transitions:
  '((dequeLen
      (val dequeLen (- (. h bottom) (. h top))))
    (ownerPush
      (action ownerPush ()
        (if (< (. h pushed) 3)
          (set-h (bottom (+ (. h bottom) 1))
                 (pushed (+ (. h pushed) 1)))
          (keep-h))))
    (ownerPop
      (action ownerPop ()
        (if (> (. h bottom) (. h top))
          (set-h (bottom (- (. h bottom) 1))
                 (ownerPopped (+ (. h ownerPopped) 1)))
          (keep-h))))
    (thiefStart
      (action thiefStart ()
        (if (and (< (. h thiefReadTop) 0)
                 (< (. h top) (. h bottom)))
          (set-h (thiefReadTop (. h top)))
          (keep-h))))
    (thiefCommitSteal
      (action thiefCommitSteal ()
        (if (>= (. h thiefReadTop) 0)
          (if (guard last-item-cas
                     (and (= (. h top) (. h thiefReadTop))
                          (< (. h top) (. h bottom))))
            (set-h (top (+ (. h top) 1))
                   (thiefStolen (+ (. h thiefStolen) 1))
                   (thiefReadTop (- 0 1)))
            (set-h (thiefReadTop (- 0 1))))
          (keep-h))))
    (step
      (action step ()
        (any ownerPush ownerPop thiefStart thiefCommitSteal))))
  safety:
  '(and (<= (+ (. h ownerPopped) (. h thiefStolen)) (. h pushed))
        (<= (. h top) (. h bottom)))
  traces:
  '((checkSafe
      (action checkSafe ()
        (all (assert safety) (keep-h))))
    (checkDouble
      (action checkDouble ()
        (all (assert (> (+ (. h ownerPopped) (. h thiefStolen)) (. h pushed)))
             (assert (not safety))
             (keep-h))))
    (pushPopTest
      (run pushPopTest
        (then init ownerPush ownerPop
              (all (assert (= (. h ownerPopped) 1))
                   (assert safety)
                   (keep-h)))))
    (pushStealTest
      (run pushStealTest
        (then init ownerPush thiefStart thiefCommitSteal ownerPop
              (all (assert (= (. h thiefStolen) 1))
                   (assert (= (. h ownerPopped) 0))
                   (assert safety)
                   (keep-h)))))
    (lastItemCasArbitrationTest
      (run lastItemCasArbitrationTest
        (then init ownerPush thiefStart ownerPop thiefCommitSteal
              (all (assert (= (. h ownerPopped) 1))
                   (assert (= (. h thiefStolen) 0))
                   (assert safety)
                   (keep-h)))))
    (missingCasDoubleTakeTest
      (run missingCasDoubleTakeTest
        (then init ownerPush thiefStart ownerPop thiefCommitNoCas checkDouble))))
  countermodels: (list MissingLastItemCasCountermodel)
  limits: "Finite 1-owner/1-thief Chase-Lev deque abstraction; does not model circular array resizing or ARMv8/TSO weak memory fences.")

(.def (MissingLastItemCasCountermodel @ WorkStealingDequeModel)
  identity: 'engineering.parallel.work-stealing-deque.missing-last-item-cas
  dropped-guard: 'last-item-cas
  step-action: "stepNoLastItemCas"
  derive-from-transition: 'thiefCommitSteal
  derive-action-name: 'thiefCommitNoCas
  expected-itf-predicate: "h.ownerPopped + h.thiefStolen > h.pushed")
