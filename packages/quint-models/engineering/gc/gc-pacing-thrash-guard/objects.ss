;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; GC pacing soft-memory-limit headroom & GC CPU thrash-limiter model.
;;; Co-located Yuanxu unit: single source of truth alongside GcPacingThrashGuard.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export GcPacingThrashGuardModel)

(.def (GcPacingThrashGuardModel @ ThreatModel.)
  identity: 'engineering.gc.gc-pacing-thrash-guard
  family: 'engineering.gc.gc-pacing-thrash-guard
  title: "GC Pacing Soft-Memory-Limit Headroom & CPU Thrash Guard"
  subdomain: 'quint.engineering.gc
  papers:
  '(("D. Cotroneo, S. Orlando, S. Russo (IEEE SRDS 2007)"
     "Characterizing Aging Phenomena of the Java Virtual Machine — GC overhead amplification under live-set growth.")
    ("M. Knyszek (Go Runtime Design, Go 1.19+)"
     "GOMEMLIMIT Soft Memory Limit & GC CPU Limiter — preventing GC thrashing death spirals near memory ceiling.")
    ("N. Bronson, A. Aghayev, A. Charapko, T. Zhu (ACM HotOS 2021)"
     "Metastable Failures in Distributed Systems — GC pause feedback loops locking services in degraded states."))
  quint-module: "gc_pacing_thrash"
  quint-file: "GcPacingThrashGuard.qnt"
  domain-dir: "engineering/gc/gc-pacing-thrash-guard"
  rules:
  '((gc-thrash-headroom GC-THRASH-HEAD quint)
    (gc-thrash-cpu GC-THRASH-CPU quint))
  dependencies:
  '((GC-THRASH-HEAD source)
    (GC-THRASH-HEAD profile)
    (GC-THRASH-HEAD method)
    (GC-THRASH-CPU source)
    (GC-THRASH-CPU profile)
    (GC-THRASH-CPU method))
  invariant: "Admission headroom shedding keeps live heap strictly below soft memory limit and GC CPU pacing bounds consecutive collection cycles per mutator window."
  limits: "Finite heap-headroom and GC-window abstraction (softMemLimit=4, safe live ceiling=3, max GC cycles per mutator window=1); models logical pacing/thrashing bounds, not object-graph pointer density or physical stop-the-world pause latency.")
