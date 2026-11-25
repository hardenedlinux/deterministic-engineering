;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Parallel lock-free Epoch-Based Reclamation (EBR) model with grace-period quiescence
;;; and weakened countermodel reclaiming a retired object while a worker remains pinned.
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
  guards: '((grace-period-quiescence "not(h.w1Pinned and h.w1Epoch <= h.retiredEpoch) and not(h.w2Pinned and h.w2Epoch <= h.retiredEpoch)"))
  transitions:
  '((quiescent "val quiescent = not(h.w1Pinned and h.w1Epoch <= h.retiredEpoch) and not(h.w2Pinned and h.w2Epoch <= h.retiredEpoch)")
    (w1Pin "action w1Pin = if (not(h.w1Pinned))\n    h' = h.with(\"w1Pinned\", true).with(\"w1Epoch\", h.globalEpoch)\n    else h' = h")
    (w1Read "action w1Read = if (h.w1Pinned)\n    h' = h.with(\"useAfterFree\", h.useAfterFree or (h.freed and h.w1Epoch <= h.retiredEpoch))\n    else h' = h")
    (w1Unpin "action w1Unpin = if (h.w1Pinned)\n    h' = h.with(\"w1Pinned\", false)\n    else h' = h")
    (w2Pin "action w2Pin = if (not(h.w2Pinned))\n    h' = h.with(\"w2Pinned\", true).with(\"w2Epoch\", h.globalEpoch)\n    else h' = h")
    (w2Read "action w2Read = if (h.w2Pinned)\n    h' = h.with(\"useAfterFree\", h.useAfterFree or (h.freed and h.w2Epoch <= h.retiredEpoch))\n    else h' = h")
    (w2Unpin "action w2Unpin = if (h.w2Pinned)\n    h' = h.with(\"w2Pinned\", false)\n    else h' = h")
    (retireObject "action retireObject = if (not(h.retired))\n    h' = h.with(\"retired\", true).with(\"retiredEpoch\", h.globalEpoch)\n    else h' = h")
    (advanceEpoch "action advanceEpoch = if (h.globalEpoch < 3)\n    h' = h.with(\"globalEpoch\", h.globalEpoch + 1)\n    else h' = h")
    (reclaim "action reclaim = if (h.retired and not(h.freed) and h.globalEpoch > h.retiredEpoch and quiescent)\n    h' = h.with(\"freed\", true)\n    else h' = h")
    (step "action step = any { w1Pin, w1Read, w1Unpin, w2Pin, w2Read, w2Unpin, retireObject, advanceEpoch, reclaim }"))
  safety: "not(h.useAfterFree) and (not(h.freed) or quiescent)"
  traces:
  '((checkSafeFreed "action checkSafeFreed = all { assert(h.freed), assert(safety), h' = h }")
    (checkNotFreed "action checkNotFreed = all { assert(not(h.freed)), assert(safety), h' = h }")
    (checkUaf "action checkUaf = all { assert(h.useAfterFree), assert(not(safety)), h' = h }")
    (safeReclaimAfterUnpinTest "run safeReclaimAfterUnpinTest = init.then(w1Pin).then(retireObject).then(advanceEpoch).then(w1Read).then(w1Unpin).then(reclaim).then(checkSafeFreed)")
    (pinnedWorkerBlocksReclaimTest "run pinnedWorkerBlocksReclaimTest = init.then(w1Pin).then(retireObject).then(advanceEpoch).then(reclaim).then(checkNotFreed)")
    (prematureReclaimUafTest "run prematureReclaimUafTest = init.then(w1Pin).then(retireObject).then(advanceEpoch).then(reclaimPremature).then(w1Read).then(checkUaf)"))
  countermodels: (list PrematureReclaimCountermodel)
  limits: "Finite 2-worker single-object EBR abstraction; does not model hardware memory fences (Acquire/Release/SeqCst) or allocator reuse.")

;; Weakened descendant: reclaims retired object after epoch bump without waiting for pinned workers to leave retiredEpoch.
(.def (PrematureReclaimCountermodel @ EpochReclamationModel)
  identity: 'engineering.parallel.epoch-reclamation.premature-reclaim
  dropped-guard: 'grace-period-quiescence
  step-action: "stepPrematureReclaim"
  counter-action: "action reclaimPremature = if (h.retired and not(h.freed) and h.globalEpoch > h.retiredEpoch)\n    h' = h.with(\"freed\", true)\n    else h' = h\n  action stepPrematureReclaim = any { step, reclaimPremature }"
  expected-itf-predicate: "h.freed == true and ((h.w1Pinned and h.w1Epoch <= h.retiredEpoch) or (h.w2Pinned and h.w2Epoch <= h.retiredEpoch))")
