;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Bounded stateful projection, session-slot LRU eviction & cascade side-map cleanup model.
;;; Co-located Yuanxu unit: single source of truth alongside BoundedProjectionEviction.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export BoundedProjectionEvictionModel)

(.def (BoundedProjectionEvictionModel @ ThreatModel.)
  identity: 'engineering.concurrency.bounded-projection-eviction
  family: 'engineering.concurrency.bounded-projection-eviction
  title: "Bounded Stateful Projection, Idle Eviction & Cascade Side-Map Cleanup"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("Y. Huang, C. Kintala, N. Kolettis & N. D. Fulton (IEEE FTCS 1995)"
     "Software Rejuvenation: Analysis, Module and Applications — bounding monotonically accumulating runtime state.")
    ("M. Jump & K. S. McKinley (ACM POPL 2007)"
     "Cork: Dynamic Memory Leak Detection for Garbage-Collected Languages — detecting growing long-lived maps and caches.")
    ("G. Xu, N. Mitchell, M. Arnold, A. Rountev, E. Schonberg & G. Sevitsky (ACM PLDI 2010)"
     "Finding Low-Utility Data Structures — evicting idle retained state and orphaned auxiliary maps."))
  quint-module: "concurrency_bounded_projection_eviction"
  quint-file: "BoundedProjectionEviction.qnt"
  domain-dir: "engineering/concurrency/bounded-projection-eviction"
  rules:
  '((conc-proj-cap CONC-PROJ-CAP quint)
    (conc-proj-orphan CONC-PROJ-ORPHAN quint))
  dependencies:
  '((CONC-PROJ-CAP source)
    (CONC-PROJ-CAP profile)
    (CONC-PROJ-CAP method)
    (CONC-PROJ-ORPHAN source)
    (CONC-PROJ-ORPHAN profile)
    (CONC-PROJ-ORPHAN method))
  invariant: "Long-lived projection/session/artifact tables stay within their entry cap, reclaim idle slots on capacity pressure without permanent lockout, and cascade-delete auxiliary side maps with zero orphaned keys."
  limits: "Finite 2-slot projection/session table abstraction; models bounded retention, idle eviction reclaimability, and cascade side-map deletion, not physical LRU hash-table internals or disk WAL compaction.")
