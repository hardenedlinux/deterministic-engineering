;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Slow-consumer bounded fan-out buffer & eviction-drain reclamation model.
;;; Co-located Yuanxu unit: single source of truth alongside SlowConsumerEviction.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export SlowConsumerEvictionModel)

(.def (SlowConsumerEvictionModel @ ThreatModel.)
  identity: 'engineering.concurrency.slow-consumer-eviction
  family: 'engineering.concurrency.slow-consumer-eviction
  title: "Slow-Consumer Fan-Out Isolation & Eviction Buffer Drain"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("M. Welsh, D. Culler, E. Brewer (ACM SOSP 2001)"
     "SEDA: An Architecture for Well-Conditioned, Scalable Internet Services — bounded per-stage queues and load conditioning.")
    ("J. Dean & L. A. Barroso (CACM 2013)"
     "The Tail at Scale — isolating slow stragglers so fan-out services preserve tail latency.")
    ("N. Bronson, A. Aghayev, A. Charapko, T. Zhu (ACM HotOS 2021)"
     "Metastable Failures in Distributed Systems — preventing stalled consumers from backing up shared producers."))
  quint-module: "concurrency_slow_consumer"
  quint-file: "SlowConsumerEviction.qnt"
  domain-dir: "engineering/concurrency/slow-consumer-eviction"
  rules:
  '((conc-slow-cap CONC-SLOW-CAP quint)
    (conc-slow-drain CONC-SLOW-DRAIN quint))
  dependencies:
  '((CONC-SLOW-CAP source)
    (CONC-SLOW-CAP profile)
    (CONC-SLOW-CAP method)
    (CONC-SLOW-DRAIN source)
    (CONC-SLOW-DRAIN profile)
    (CONC-SLOW-DRAIN method))
  invariant: "Per-consumer fan-out queue never exceeds its cap and evicting a stalled consumer drains all retained frames with zero orphaned buffers."
  limits: "Finite 2-frame slow-subscriber fan-out abstraction; models per-subscriber bounded buffering and eviction cleanup, not kernel TCP send-window dynamics or OS socket teardown latency.")
