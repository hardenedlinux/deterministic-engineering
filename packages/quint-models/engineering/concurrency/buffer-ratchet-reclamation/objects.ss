;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Reusable buffer pool high-water-mark ratchet & bounded-retain reclamation model.
;;; Co-located Yuanxu unit: single source of truth alongside BufferRatchetReclamation.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export BufferRatchetReclamationModel)

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
  limits: "Finite buffer-pool abstraction (normal=1 unit, spike=4 units, pool slot ceiling=1, retain ceiling=1); models logical pool watermark retention, not OS allocator page fragmentation or GC compaction pauses.")
