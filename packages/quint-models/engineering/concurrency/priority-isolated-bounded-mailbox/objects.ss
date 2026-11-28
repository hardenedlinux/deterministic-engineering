;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Priority-isolated bounded multi-tier mailbox, active cancelled-job
;;; compaction, and latest-wins progress watch channel model (SM11).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export PriorityIsolatedBoundedMailboxModel)

(.def (PriorityIsolatedBoundedMailboxModel @ ThreatModel.)
  identity: 'engineering.concurrency.priority-isolated-bounded-mailbox
  family: 'engineering.concurrency.priority-isolated-bounded-mailbox
  title: "Priority-Isolated Bounded Mailbox, Active Compaction & Latest-Wins Watch"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("M. Welsh, D. Culler & E. Brewer (ACM SOSP 2001)"
     "SEDA: An Architecture for Well-Conditioned, Scalable Internet Services — bounded admission control and explicit load shedding.")
    ("H. Zhou et al. (ACM SoCC 2018)"
     "Overload Control for Scaling WeChat Microservices (DAGOR) — priority-aware load shedding preventing low-priority floods from starving high-priority work.")
    ("A. Demers, S. Keshav & S. Shenker (ACM SIGCOMM 1989)"
     "Analysis and Simulation of a Fair Queueing Algorithm — weighted fair draining preventing lower-tier starvation.")
    ("J. Dean & L. A. Barroso (CACM 2013)"
     "The Tail at Scale — keeping interactive latency bounded under concurrent background bursts."))
  quint-module: "concurrency_priority_isolated_bounded_mailbox"
  quint-file: "PriorityIsolatedBoundedMailbox.qnt"
  domain-dir: "engineering/concurrency/priority-isolated-bounded-mailbox"
  rules:
  '((conc-mb-priority-isolation CONC-MB-PRIORITY-ISOLATION quint)
    (conc-mb-bounded-shedding CONC-MB-BOUNDED-SHEDDING quint)
    (conc-mb-zombie-compaction CONC-MB-ZOMBIE-COMPACTION quint))
  dependencies:
  '((CONC-MB-PRIORITY-ISOLATION source)
    (CONC-MB-PRIORITY-ISOLATION profile)
    (CONC-MB-PRIORITY-ISOLATION method)
    (CONC-MB-BOUNDED-SHEDDING source)
    (CONC-MB-BOUNDED-SHEDDING profile)
    (CONC-MB-BOUNDED-SHEDDING method)
    (CONC-MB-ZOMBIE-COMPACTION source)
    (CONC-MB-ZOMBIE-COMPACTION profile)
    (CONC-MB-ZOMBIE-COMPACTION method))
  invariant: "Separate per-tier bounded channels shed saturated low-priority bursts without starving high-priority queries, cancelled callers are actively compacted from queue slots, weighted fair draining avoids starvation, and latest-wins progress snapshots stay within O(1) slot."
  limits: "Finite 2-slot per-tier priority mailbox and 1-slot watch channel abstraction; verifies priority isolation under overload, bounded shedding, cancelled-job compaction, and monotonic watch progress, not OS thread scheduling.")
