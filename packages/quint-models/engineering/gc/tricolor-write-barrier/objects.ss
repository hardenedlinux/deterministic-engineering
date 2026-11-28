;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Concurrent tri-color GC marking model with Dijkstra insertion write barrier.
;;; Co-located Yuanxu unit: single source of truth alongside TricolorWriteBarrier.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export TricolorWriteBarrierModel)

(.def (TricolorWriteBarrierModel @ ThreatModel.)
  identity: 'engineering.gc.tricolor-write-barrier
  family: 'engineering.gc.tricolor-write-barrier
  title: "Concurrent Tri-Color GC & Dijkstra Write Barrier"
  subdomain: 'quint.engineering.gc
  papers:
  '(("E. W. Dijkstra, L. Lamport, A. J. Martin, C. S. Scholten & E. F. M. Steffens (CACM 1978)"
     "On-the-Fly Garbage Collection: An Exercise in Cooperation — strong tri-color invariant and insertion barrier.")
    ("R. Jones, A. Hosking & E. Moss (2011)"
     "The Garbage Collection Handbook: concurrent marking invariants and write-barrier soundness."))
  quint-module: "gc_tricolor_barrier"
  quint-file: "TricolorWriteBarrier.qnt"
  domain-dir: "engineering/gc/tricolor-write-barrier"
  rules:
  '((gc-tricolor-strong GC-TRICOLOR-STRONG quint)
    (gc-tricolor-no-barrier GC-NO-BARRIER quint))
  dependencies:
  '((GC-TRICOLOR-STRONG source)
    (GC-TRICOLOR-STRONG profile)
    (GC-TRICOLOR-STRONG method)
    (GC-NO-BARRIER source)
    (GC-NO-BARRIER profile)
    (GC-NO-BARRIER method))
  invariant: "Strong tri-color invariant holds during marking (no Black->White edge) and sweep never reclaims a reachable live object."
  limits: "Finite 3-object tri-color marking abstraction; does not model hardware weak memory ordering, compaction, or allocator fragmentation.")
