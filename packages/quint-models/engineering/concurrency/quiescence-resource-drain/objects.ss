;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Cyclic resource conservation and error/cancellation quiescence drain model.
;;; Co-located Yuanxu unit: single source of truth alongside QuiescenceResourceDrain.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export QuiescenceResourceDrainModel
        ErrorPathLeakCountermodel
        CancelDrainLeakCountermodel)

(.def (QuiescenceResourceDrainModel @ ThreatModel.)
  identity: 'engineering.concurrency.quiescence-resource-drain
  family: 'engineering.concurrency.quiescence-resource-drain
  title: "Cyclic Resource Conservation & Error/Cancel Quiescence Drain"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("D. Yuan et al. (USENIX OSDI 2014)"
     "Simple Testing Can Prevent Most Critical Failures — error-handling cleanup omissions drive catastrophic failures.")
    ("C. Calcagno, D. Distefano, P. O'Hearn, H. Yang (ACM POPL 2009)"
     "Compositional Shape Analysis by means of Bi-Abduction — compositional resource-leak verification (Meta Infer).")
    ("T. Tu, X. Liu, L. Song, Y. Zhang (ACM ASPLOS 2019)"
     "Understanding Real-World Concurrency Bugs in Go — blocked-channel goroutine leaks on cancellation.")
    ("B. Qin, Y. Chen, Z. Yu, L. Song, Y. Zhang (ACM PLDI 2020)"
     "Understanding Memory and Thread Safety Practices and Issues in Real-World Rust Programs — handle/task leaks."))
  quint-module: "concurrency_quiescence_drain"
  quint-file: "QuiescenceResourceDrain.qnt"
  domain-dir: "engineering/concurrency/quiescence-resource-drain"
  quint-imports: '()
  rules:
  '((conc-drain-error CONC-DRAIN-ERR quint)
    (conc-drain-cancel CONC-DRAIN-CAN quint))
  dependencies:
  '((CONC-DRAIN-ERR source)
    (CONC-DRAIN-ERR profile)
    (CONC-DRAIN-ERR method)
    (CONC-DRAIN-CAN source)
    (CONC-DRAIN-CAN profile)
    (CONC-DRAIN-CAN method))
  invariant: "Held resources exactly match active work across normal, error, and cancellation exits, returning strictly to zero at quiescence."
  parameters: '()
  state:
  '((activeWork "int" "0")
    (heldHandles "int" "0")
    (pendingError "bool" "false")
    (pendingCancel "bool" "false")
    (cyclesCompleted "int" "0"))
  guards:
  '((error-path-release (- (. h heldHandles) 1))
    (cancel-drain-release (- (. h heldHandles) 1)))
  transitions:
  '((acquireWork
      (action acquireWork ()
        (if (and (< (. h activeWork) 2)
                 (< (. h heldHandles) 2)
                 (< (. h cyclesCompleted) 4))
          (set-h (activeWork (+ (. h activeWork) 1))
                 (heldHandles (+ (. h heldHandles) 1)))
          (keep-h))))
    (completeNormal
      (action completeNormal ()
        (if (and (> (. h activeWork) 0)
                 (not (. h pendingError))
                 (not (. h pendingCancel)))
          (set-h (activeWork (- (. h activeWork) 1))
                 (heldHandles (- (. h heldHandles) 1))
                 (cyclesCompleted (+ (. h cyclesCompleted) 1)))
          (keep-h))))
    (injectError
      (action injectError ()
        (if (and (> (. h activeWork) 0)
                 (not (. h pendingError))
                 (not (. h pendingCancel)))
          (set-h (pendingError #t))
          (keep-h))))
    (finishWithError
      (action finishWithError ()
        (if (and (> (. h activeWork) 0) (. h pendingError))
          (set-h (activeWork (- (. h activeWork) 1))
                 (pendingError #f)
                 (heldHandles (guard error-path-release (- (. h heldHandles) 1) (. h heldHandles)))
                 (cyclesCompleted (+ (. h cyclesCompleted) 1)))
          (keep-h))))
    (injectCancel
      (action injectCancel ()
        (if (and (> (. h activeWork) 0)
                 (not (. h pendingCancel))
                 (not (. h pendingError)))
          (set-h (pendingCancel #t))
          (keep-h))))
    (finishWithCancel
      (action finishWithCancel ()
        (if (and (> (. h activeWork) 0) (. h pendingCancel))
          (set-h (activeWork (- (. h activeWork) 1))
                 (pendingCancel #f)
                 (heldHandles (guard cancel-drain-release (- (. h heldHandles) 1) (. h heldHandles)))
                 (cyclesCompleted (+ (. h cyclesCompleted) 1)))
          (keep-h))))
    (step
      (action step ()
        (any acquireWork completeNormal injectError finishWithError injectCancel finishWithCancel))))
  safety:
  '(and (= (. h heldHandles) (. h activeWork))
        (<= (. h heldHandles) 2)
        (or (> (. h activeWork) 0) (= (. h heldHandles) 0)))
  traces:
  '((checkQuiescent
      (action checkQuiescent ()
        (all (assert (= (. h activeWork) 0))
             (assert (= (. h heldHandles) 0))
             (assert safety)
             (keep-h))))
    (checkLeaked
      (action checkLeaked ()
        (all (assert (> (. h heldHandles) (. h activeWork)))
             (assert (not safety))
             (keep-h))))
    (cleanCyclicDrainTest
      (run cleanCyclicDrainTest
        (then init acquireWork completeNormal acquireWork injectError finishWithError acquireWork injectCancel finishWithCancel checkQuiescent)))
    (errorLeakRefutedTest
      (run errorLeakRefutedTest
        (then init acquireWork injectError finishWithErrorLeaky checkLeaked)))
    (cancelLeakRefutedTest
      (run cancelLeakRefutedTest
        (then init acquireWork injectCancel finishWithCancelLeaky checkLeaked))))
  countermodels: (list ErrorPathLeakCountermodel CancelDrainLeakCountermodel)
  limits: "Finite 2-slot, 4-cycle resource lifecycle abstraction; models logical handle/task conservation across normal, error, and cancel paths, not OS kernel FD tables or allocator fragmentation.")

(.def (ErrorPathLeakCountermodel @ QuiescenceResourceDrainModel)
  identity: 'engineering.concurrency.quiescence-resource-drain.error-path-leak
  dropped-guard: 'error-path-release
  step-action: "stepErrorPathLeak"
  derive-from-transition: 'finishWithError
  derive-action-name: 'finishWithErrorLeaky
  expected-itf-predicate: "h.heldHandles > h.activeWork")

(.def (CancelDrainLeakCountermodel @ QuiescenceResourceDrainModel)
  identity: 'engineering.concurrency.quiescence-resource-drain.cancel-drain-leak
  dropped-guard: 'cancel-drain-release
  step-action: "stepCancelDrainLeak"
  derive-from-transition: 'finishWithCancel
  derive-action-name: 'finishWithCancelLeaky
  expected-itf-predicate: "h.heldHandles > h.activeWork")
