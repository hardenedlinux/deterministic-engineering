;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Domain-owned bounded backpressure & memory ownership formal model.
;;; Co-located Yuanxu unit: single source of truth alongside BackpressureOwners.qnt and README.org.
;;; Models disjoint ownership partition conservation (queued, running, returned, cleanup),
;;; bounded admission/queue capacity, and non-abortable cleanup permit retention under cancellation.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export BackpressureOwnersModel)

(.def (BackpressureOwnersModel @ ThreatModel.)
  identity: 'engineering.concurrency.backpressure-memory
  family: 'engineering.concurrency.backpressure-memory
  title: "Bounded Backpressure & Disjoint Memory-Ownership Conservation"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("Reactive Streams Specification (2015)"
     "Asynchronous stream processing with non-blocking bounded backpressure.")
    ("J. Mace, R. Roelke & R. Fonseca (SOSP 2015)"
     "Pivot Tracing / End-to-end bounded resource ownership and queue isolation across async boundaries.")
    ("Deterministic Engineering (10.25 / 10.77)"
     "Bounded ownership conservation across queued, running, returned, and non-abortable cleanup states."))
  quint-module: "BackpressureOwners"
  quint-file: "BackpressureOwners.qnt"
  domain-dir: "engineering/concurrency/backpressure-memory"
  rules:
  '((backpressure-safe BP-OWN-SAFE quint)
    (backpressure-countermodel BP-OWN-COUNTER quint))
  dependencies:
  '((BP-OWN-SAFE source)
    (BP-OWN-SAFE profile)
    (BP-OWN-SAFE method)
    (BP-OWN-COUNTER source)
    (BP-OWN-COUNTER profile)
    (BP-OWN-COUNTER method))
  invariant: "Every admitted job belongs to exactly one mutually disjoint ownership state (queued, running, returned, or cleanup), total admitted permits never exceed limit, queued jobs never exceed queueLimit, and completed (done) jobs hold no active permit."
  limits: "Finite-state bounded ownership abstraction over 4 discrete job IDs (limit=2, queueLimit=1); makes no Rust scheduler, allocator, byte-accounting, or kernel memory-reclamation claim.")
