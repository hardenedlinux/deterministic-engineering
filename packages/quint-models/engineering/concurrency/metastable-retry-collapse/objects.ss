;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Metastable overload failure, retry-budget amplification & load-shedding recovery model.
;;; Co-located Yuanxu unit: single source of truth alongside MetastableRetryCollapse.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export MetastableRetryCollapseModel)

(.def (MetastableRetryCollapseModel @ ThreatModel.)
  identity: 'engineering.concurrency.metastable-retry-collapse
  family: 'engineering.concurrency.metastable-retry-collapse
  title: "Metastable Retry Collapse & Congestion-Aware Load Shedding"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("N. Bronson, A. Aghayev, A. Charapko, T. Zhu (ACM HotOS 2021)"
     "Metastable Failures in Distributed Systems — self-sustaining degraded states sustained by retry feedback loops.")
    ("L. Huang et al. (USENIX OSDI 2022)"
     "Metastable Failures in the Wild — empirical study of 22 production cloud outages sustained after transient triggers.")
    ("H. Zhou et al. (ACM SoCC 2018)"
     "Overload Control for Scaling WeChat Microservices (DAGOR) — queue-delay admission & load shedding.")
    ("I. Cho et al. (USENIX OSDI 2020)"
     "Overload Control for us-scale RPCs with Breakwater — server-driven credit admission bounds."))
  quint-module: "concurrency_metastable_retry"
  quint-file: "MetastableRetryCollapse.qnt"
  domain-dir: "engineering/concurrency/metastable-retry-collapse"
  rules:
  '((conc-meta-shed CONC-META-SHED quint)
    (conc-meta-retry CONC-META-RETRY quint))
  dependencies:
  '((CONC-META-SHED source)
    (CONC-META-SHED profile)
    (CONC-META-SHED method)
    (CONC-META-RETRY source)
    (CONC-META-RETRY profile)
    (CONC-META-RETRY method))
  invariant: "Congestion-aware load shedding and an explicit retry budget keep admitted queue depth and pending retry amplification within safe recovery bounds."
  limits: "Finite single-stage queue and retry-budget abstraction (queue cap=2, retry budget=1); models overload amplification and recovery bounds, not continuous service-time distributions or multi-hop network propagation delays.")
