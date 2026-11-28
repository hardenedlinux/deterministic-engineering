;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Cyclic resource conservation and error/cancellation quiescence drain model.
;;; Co-located Yuanxu unit: single source of truth alongside QuiescenceResourceDrain.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export QuiescenceResourceDrainModel)

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
  limits: "Finite 2-slot, 4-cycle resource lifecycle abstraction; models logical handle/task conservation across normal, error, and cancel paths, not OS kernel FD tables or allocator fragmentation.")
