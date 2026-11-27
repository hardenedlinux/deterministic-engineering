;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Hazard Pointers under x86-TSO Store-Buffer Reordering engineering model.
;;; Co-located Yuanxu unit: single source of truth alongside HazardPointersTso.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export HazardPointersTsoModel)

(.def (HazardPointersTsoModel @ ThreatModel.)
  identity: 'engineering.parallel.hazard-pointers-tso
  family: 'engineering.parallel.hazard-pointers-tso
  title: "Hazard Pointers under x86-TSO Store-Buffer Reordering"
  subdomain: 'quint.engineering.parallel
  papers:
  '(("M. M. Michael (IEEE TPDS 2004)"
     "Hazard Pointers: Safe Memory Reclamation for Lock-Free Objects — publish-then-validate protocol.")
    ("P. Sewell, S. Sarkar, S. Owens, F. Zappa Nardelli & M. O. Myreen (CACM 2010)"
     "x86-TSO: A Rigorous and Usable Programmer's Model for x86 Multiprocessors — store-load buffering and MFENCE."))
  quint-module: "hazard_pointers_tso"
  quint-file: "HazardPointersTso.qnt"
  domain-dir: "engineering/parallel/hazard-pointers-tso"
  rules:
  '((tso-store-load-fence PAR-HP-TSO-FENCE quint))
  dependencies:
  '((PAR-HP-TSO-FENCE source)
    (PAR-HP-TSO-FENCE profile)
    (PAR-HP-TSO-FENCE method))
  invariant: "A reader thread never dereferences a node that the reclaimer has already freed (zero Use-After-Free under x86-TSO store-buffer reordering)."
  limits: "Finite single-node, single-reader, single-reclaimer x86-TSO store-buffer abstraction; does not model ARM/POWER non-multi-copy-atomic reordering or dynamic HP array resizing.")
