;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Parallel lock-free Epoch-Based Reclamation (EBR) model with grace-period quiescence.
;;; Co-located Yuanxu unit: single source of truth alongside EpochReclamation.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export EpochReclamationModel)

(.def (EpochReclamationModel @ ThreatModel.)
  identity: 'engineering.parallel.epoch-reclamation
  family: 'engineering.parallel.epoch-reclamation
  title: "Lock-Free Epoch-Based Reclamation (EBR) Grace Period"
  subdomain: 'quint.engineering.parallel
  papers:
  '(("K. Fraser (Cambridge PhD Thesis 2004)"
     "Practical Lock-Freedom: Epoch-Based Reclamation (EBR) pinning and grace-period quiescence.")
    ("T. E. Hart, P. E. McKenney, A. D. Brown & J. Walpole (JPDC 2007)"
     "Performance of Memory Reclamation for Lockless Synchronization: EBR vs. QSBR vs. Hazard Pointers."))
  quint-module: "parallel_epoch_reclamation"
  quint-file: "EpochReclamation.qnt"
  domain-dir: "engineering/parallel/epoch-reclamation"
  rules:
  '((par-ebr-safe PAR-EBR-SAFE quint)
    (par-ebr-premature PAR-EBR-PREMATURE quint))
  dependencies:
  '((PAR-EBR-SAFE source)
    (PAR-EBR-SAFE profile)
    (PAR-EBR-SAFE method)
    (PAR-EBR-PREMATURE source)
    (PAR-EBR-PREMATURE profile)
    (PAR-EBR-PREMATURE method))
  invariant: "A retired shared object is reclaimed only after all pinned workers observe an epoch strictly greater than retiredEpoch, preventing use-after-free."
  limits: "Finite 2-worker single-object EBR abstraction; does not model hardware memory fences (Acquire/Release/SeqCst) or allocator reuse.")
