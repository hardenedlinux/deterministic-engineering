;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Reusable buffer pool high-water-mark ratchet & bounded-retain reclamation model.
;;; Co-located Yuanxu unit: single source of truth alongside BufferRatchetReclamation.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export BufferRatchetReclamationModel
        SpikePoolPoisonCountermodel
        PoolSlotOverflowCountermodel)

(.def (BufferRatchetReclamationModel @ ThreatModel.)
  identity: 'engineering.concurrency.buffer-ratchet-reclamation
  family: 'engineering.concurrency.buffer-ratchet-reclamation
  title: "Buffer Pool Watermark Ratchet & Bounded-Retain Reclamation"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("M. Jump & K. S. McKinley (ACM POPL 2007)"
     "Cork: Dynamic Memory Leak Detection for Garbage-Collected Languages — semantic retention & heap bloat across cycles.")
    ("G. Xu et al. (ACM PLDI 2010)"
     "Finding Low-Utility Data Structures & Detecting Inefficiently-Used Containers to Avoid Bloat.")
    ("D. Cotroneo, S. Orlando, S. Russo (IEEE SRDS 2007)"
     "Characterizing Aging Phenomena of the Java Virtual Machine — internal container & pool bloat over time.")
    ("B. Powers, D. Tench, E. D. Berger, A. McGregor (ACM PLDI 2019)"
     "Mesh: Compacting Memory Management for C/C++ — non-shrinking capacity & fragmentation bounds."))
  quint-module: "concurrency_buffer_ratchet"
  quint-file: "BufferRatchetReclamation.qnt"
  domain-dir: "engineering/concurrency/buffer-ratchet-reclamation"
  quint-imports: '()
  rules:
  '((conc-ratchet-cap CONC-RATCHET-CAP quint)
    (conc-ratchet-slots CONC-RATCHET-SLOTS quint))
  dependencies:
  '((CONC-RATCHET-CAP source)
    (CONC-RATCHET-CAP profile)
    (CONC-RATCHET-CAP method)
    (CONC-RATCHET-SLOTS source)
    (CONC-RATCHET-SLOTS profile)
    (CONC-RATCHET-SLOTS method))
  invariant: "Reusable buffer pools enforce both a per-buffer retain ceiling and a slot ceiling so spike payloads never poison quiescent retained memory."
  parameters: '()
  state:
  '((activeSmall "int" "0")
    (activeSpike "int" "0")
    (pooledSlots "int" "0")
    (pooledBytes "int" "0"))
  guards:
  '((pool-max-retain-cap (<= 4 1))
    (pool-slot-cap (< (. h pooledSlots) 1)))
  transitions:
  '((acquireSmallFresh
      (action acquireSmallFresh ()
        (if (< (. h activeSmall) 2)
          (set-h (activeSmall (+ (. h activeSmall) 1)))
          (keep-h))))
    (acquireSmallFromPool
      (action acquireSmallFromPool ()
        (if (and (< (. h activeSmall) 2) (> (. h pooledSlots) 0))
          (set-h (activeSmall (+ (. h activeSmall) 1))
                 (pooledSlots (- (. h pooledSlots) 1))
                 (pooledBytes (- (. h pooledBytes) 1)))
          (keep-h))))
    (releaseSmall
      (action releaseSmall ()
        (if (and (> (. h activeSmall) 0)
                 (guard pool-slot-cap (< (. h pooledSlots) 1)))
          (set-h (activeSmall (- (. h activeSmall) 1))
                 (pooledSlots (+ (. h pooledSlots) 1))
                 (pooledBytes (+ (. h pooledBytes) 1)))
          (if (> (. h activeSmall) 0)
            (set-h (activeSmall (- (. h activeSmall) 1)))
            (keep-h)))))
    (acquireSpike
      (action acquireSpike ()
        (if (= (. h activeSpike) 0)
          (set-h (activeSpike 1))
          (keep-h))))
    (releaseSpike
      (action releaseSpike ()
        (if (and (> (. h activeSpike) 0)
                 (guard pool-max-retain-cap (<= 4 1)))
          (set-h (activeSpike (- (. h activeSpike) 1))
                 (pooledSlots (+ (. h pooledSlots) 1))
                 (pooledBytes (+ (. h pooledBytes) 4)))
          (if (> (. h activeSpike) 0)
            (set-h (activeSpike (- (. h activeSpike) 1)))
            (keep-h)))))
    (step
      (action step ()
        (any acquireSmallFresh acquireSmallFromPool releaseSmall acquireSpike releaseSpike))))
  safety:
  '(and (<= (. h pooledSlots) 1)
        (<= (. h pooledBytes) 1)
        (= (. h pooledBytes) (. h pooledSlots))
        (or (> (+ (. h activeSmall) (. h activeSpike)) 0)
            (<= (. h pooledBytes) 1)))
  traces:
  '((checkBoundedQuiescent
      (action checkBoundedQuiescent ()
        (all (assert (= (. h activeSmall) 0))
             (assert (= (. h activeSpike) 0))
             (assert (<= (. h pooledBytes) 1))
             (assert safety)
             (keep-h))))
    (checkRatchetViolation
      (action checkRatchetViolation ()
        (all (assert (> (. h pooledBytes) 1))
             (assert (not safety))
             (keep-h))))
    (spikeDiscardedCleanlyTest
      (run spikeDiscardedCleanlyTest
        (then init acquireSmallFresh releaseSmall acquireSmallFromPool releaseSmall acquireSpike releaseSpike checkBoundedQuiescent)))
    (spikePoisonRefutedTest
      (run spikePoisonRefutedTest
        (then init acquireSpike releaseSpikeUnbounded checkRatchetViolation)))
    (slotOverflowRefutedTest
      (run slotOverflowRefutedTest
        (then init acquireSmallFresh releaseSmall acquireSmallFresh releaseSmallUnbounded checkRatchetViolation))))
  countermodels: (list SpikePoolPoisonCountermodel PoolSlotOverflowCountermodel)
  limits: "Finite buffer-pool abstraction (normal=1 unit, spike=4 units, pool slot ceiling=1, retain ceiling=1); models logical pool watermark retention, not OS allocator page fragmentation or GC compaction pauses.")

(.def (SpikePoolPoisonCountermodel @ BufferRatchetReclamationModel)
  identity: 'engineering.concurrency.buffer-ratchet-reclamation.spike-pool-poison
  dropped-guard: 'pool-max-retain-cap
  step-action: "stepSpikePoolPoison"
  derive-from-transition: 'releaseSpike
  derive-action-name: 'releaseSpikeUnbounded
  expected-itf-predicate: "h.pooledBytes > 1")

(.def (PoolSlotOverflowCountermodel @ BufferRatchetReclamationModel)
  identity: 'engineering.concurrency.buffer-ratchet-reclamation.pool-slot-overflow
  dropped-guard: 'pool-slot-cap
  step-action: "stepPoolSlotOverflow"
  derive-from-transition: 'releaseSmall
  derive-action-name: 'releaseSmallUnbounded
  expected-itf-predicate: "h.pooledSlots > 1")
