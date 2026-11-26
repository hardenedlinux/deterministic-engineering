;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Parallel lock-free Epoch-Based Reclamation (EBR) model with grace-period quiescence.
;;; Typed structural AST + auto-derived premature-reclaim countermodel via (guard ...).
(import :clan/poo/object
        (only-in "../threat-capabilities/objects.ss" ThreatModel.))
(export EpochReclamationModel PrematureReclaimCountermodel)

(.def (EpochReclamationModel @ ThreatModel.)
  identity: 'engineering.parallel.epoch-reclamation
  family: 'engineering.parallel.epoch-reclamation
  quint-module: "parallel_epoch_reclamation"
  quint-file: "EpochReclamation.qnt"
  domain-dir: "engineering/parallel/epoch-reclamation"
  quint-imports: '()
  rules: '((par-ebr-safe PAR-EBR-SAFE quint)
           (par-ebr-premature PAR-EBR-PREMATURE quint))
  dependencies: '((PAR-EBR-SAFE source) (PAR-EBR-SAFE profile) (PAR-EBR-SAFE method)
                  (PAR-EBR-PREMATURE source) (PAR-EBR-PREMATURE profile) (PAR-EBR-PREMATURE method))
  invariant: "A retired shared object is reclaimed only after all pinned workers observe an epoch strictly greater than retiredEpoch, preventing use-after-free."
  parameters: '()
  state: '((globalEpoch "int" "1")
           (w1Pinned "bool" "false")
           (w1Epoch "int" "0")
           (w2Pinned "bool" "false")
           (w2Epoch "int" "0")
           (retired "bool" "false")
           (retiredEpoch "int" "0")
           (freed "bool" "false")
           (useAfterFree "bool" "false"))
  guards: '((grace-period-quiescence
             (and (not (and (. h w1Pinned) (<= (. h w1Epoch) (. h retiredEpoch))))
                  (not (and (. h w2Pinned) (<= (. h w2Epoch) (. h retiredEpoch)))))))
  transitions:
  '((quiescent
     (val quiescent
       (and (not (and (. h w1Pinned) (<= (. h w1Epoch) (. h retiredEpoch))))
            (not (and (. h w2Pinned) (<= (. h w2Epoch) (. h retiredEpoch)))))))
    (w1Pin
     (action w1Pin ()
       (if (not (. h w1Pinned))
         (set-h (w1Pinned #t) (w1Epoch (. h globalEpoch)))
         (keep-h))))
    (w1Read
     (action w1Read ()
       (if (. h w1Pinned)
         (set-h (useAfterFree (or (. h useAfterFree) (and (. h freed) (<= (. h w1Epoch) (. h retiredEpoch))))))
         (keep-h))))
    (w1Unpin
     (action w1Unpin ()
       (if (. h w1Pinned) (set-h (w1Pinned #f)) (keep-h))))
    (w2Pin
     (action w2Pin ()
       (if (not (. h w2Pinned))
         (set-h (w2Pinned #t) (w2Epoch (. h globalEpoch)))
         (keep-h))))
    (w2Read
     (action w2Read ()
       (if (. h w2Pinned)
         (set-h (useAfterFree (or (. h useAfterFree) (and (. h freed) (<= (. h w2Epoch) (. h retiredEpoch))))))
         (keep-h))))
    (w2Unpin
     (action w2Unpin ()
       (if (. h w2Pinned) (set-h (w2Pinned #f)) (keep-h))))
    (retireObject
     (action retireObject ()
       (if (not (. h retired))
         (set-h (retired #t) (retiredEpoch (. h globalEpoch)))
         (keep-h))))
    (advanceEpoch
     (action advanceEpoch ()
       (if (< (. h globalEpoch) 3)
         (set-h (globalEpoch (+ (. h globalEpoch) 1)))
         (keep-h))))
    (reclaim
     (action reclaim ()
       (if (and (. h retired)
                (not (. h freed))
                (> (. h globalEpoch) (. h retiredEpoch))
                (guard grace-period-quiescence quiescent))
         (set-h (freed #t))
         (keep-h))))
    (step
     (action step ()
       (any w1Pin w1Read w1Unpin w2Pin w2Read w2Unpin retireObject advanceEpoch reclaim))))
  safety:
  '(and (not (. h useAfterFree))
        (or (not (. h freed)) quiescent))
  traces:
  '((checkSafeFreed (action checkSafeFreed () (all (assert (. h freed)) (assert safety) (keep-h))))
    (checkNotFreed (action checkNotFreed () (all (assert (not (. h freed))) (assert safety) (keep-h))))
    (checkUaf (action checkUaf () (all (assert (. h useAfterFree)) (assert (not safety)) (keep-h))))
    (safeReclaimAfterUnpinTest
     (run safeReclaimAfterUnpinTest
       (then init w1Pin retireObject advanceEpoch w1Read w1Unpin reclaim checkSafeFreed)))
    (pinnedWorkerBlocksReclaimTest
     (run pinnedWorkerBlocksReclaimTest
       (then init w1Pin retireObject advanceEpoch reclaim checkNotFreed)))
    (prematureReclaimUafTest
     (run prematureReclaimUafTest
       (then init w1Pin retireObject advanceEpoch reclaimPremature w1Read checkUaf))))
  countermodels: (list PrematureReclaimCountermodel)
  limits: "Finite 2-worker single-object EBR abstraction; does not model hardware memory fences (Acquire/Release/SeqCst) or allocator reuse.")

;; Weakened descendant: reclaims retired object after epoch bump without waiting for pinned workers to leave retiredEpoch.
(.def (PrematureReclaimCountermodel @ EpochReclamationModel)
  identity: 'engineering.parallel.epoch-reclamation.premature-reclaim
  dropped-guard: 'grace-period-quiescence
  step-action: "stepPrematureReclaim"
  derive-from-transition: 'reclaim
  derive-action-name: 'reclaimPremature
  expected-itf-predicate: "h.freed == true and ((h.w1Pinned and h.w1Epoch <= h.retiredEpoch) or (h.w2Pinned and h.w2Epoch <= h.retiredEpoch))")
