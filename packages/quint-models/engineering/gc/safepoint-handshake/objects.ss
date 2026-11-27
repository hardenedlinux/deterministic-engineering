;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Concurrent GC mutator/collector safepoint handshake protocol (Doligez-Leroy / SATB).
;;; Co-located Yuanxu unit: single source of truth alongside SafepointHandshake.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export SafepointHandshakeModel)

(.def (SafepointHandshakeModel @ ThreatModel.)
  identity: 'engineering.gc.safepoint-handshake
  family: 'engineering.gc.safepoint-handshake
  title: "Concurrent GC Mutator/Collector Safepoint Handshake"
  subdomain: 'quint.engineering.gc
  papers:
  '(("D. Doligez & X. Leroy (ACM POPL 1993)"
     "A Concurrent, Generational Garbage Collector for a Multithreaded Implementation of ML — two-phase barrier handshake.")
    ("D. Doligez & G. Gonthier (ACM POPL 1994)"
     "Portable, Unobtrusive Garbage Collection for Multiprocessor Systems."))
  quint-module: "gc_safepoint_handshake"
  quint-file: "SafepointHandshake.qnt"
  domain-dir: "engineering/gc/safepoint-handshake"
  rules:
  '((gc-hs-safe GC-HS-SAFE quint)
    (gc-hs-skip GC-HS-SKIP quint))
  dependencies:
  '((GC-HS-SAFE source)
    (GC-HS-SAFE profile)
    (GC-HS-SAFE method)
    (GC-HS-SKIP source)
    (GC-HS-SKIP profile)
    (GC-HS-SKIP method))
  invariant: "During concurrent Mark phase, every mutator has enabled its write barrier and no unbarriered store occurs."
  limits: "Finite 2-mutator safepoint handshake abstraction; does not model OS thread preemption, page-fault polling, or stack scanning.")
