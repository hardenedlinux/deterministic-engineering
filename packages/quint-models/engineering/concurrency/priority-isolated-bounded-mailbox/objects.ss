;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Priority-isolated bounded multi-tier mailbox, active cancelled-job
;;; compaction, and latest-wins progress watch channel model (SM11).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export PriorityIsolatedBoundedMailboxModel
        SharedChannelPriorityInversionCountermodel
        UnboundedQueueGrowthCountermodel
        ZombieSlotLeakCountermodel)

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
  quint-imports: '()
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
  parameters: '()
  state:
  '((hiQueue "int" "0")
    (loQueue "int" "0")
    (zombieLo "int" "0")
    (hiBurst "int" "0")
    (hiStarved "bool" "false")
    (progressSlots "int" "0")
    (producedWater "int" "0")
    (observedWater "int" "0")
    (shedLoCount "int" "0"))
  guards:
  '((isolate-priority-ingress false)
    (bound-ingress-capacity true)
    (compact-cancelled-zombies true))
  transitions:
  '((submitHi
      (action submitHi ()
        (if (< (. h hiQueue) 2)
          (if (and (guard isolate-priority-ingress false true) (>= (. h loQueue) 2))
            (set-h (hiStarved true))
            (set-h (hiQueue (+ (. h hiQueue) 1))))
          (keep-h))))
    (submitLo
      (action submitLo ()
        (if (< (. h loQueue) 2)
          (set-h (loQueue (+ (. h loQueue) 1)))
          (if (not (guard bound-ingress-capacity true false))
            (set-h (loQueue (+ (. h loQueue) 1)))
            (set-h (shedLoCount (+ (. h shedLoCount) 1)))))))
    (cancelLo
      (action cancelLo ()
        (if (> (. h loQueue) 0)
          (if (guard compact-cancelled-zombies true false)
            (set-h (loQueue (- (. h loQueue) 1)))
            (set-h (zombieLo (+ (. h zombieLo) 1))))
          (keep-h))))
    (drainOne
      (action drainOne ()
        (if (and (> (. h loQueue) 0) (or (= (. h hiQueue) 0) (>= (. h hiBurst) 2)))
          (set-h (loQueue (- (. h loQueue) 1))
                 (hiBurst 0))
          (if (> (. h hiQueue) 0)
            (set-h (hiQueue (- (. h hiQueue) 1))
                   (hiBurst (+ (. h hiBurst) 1)))
            (keep-h)))))
    (publishProgress
      (action publishProgress ()
        (if (< (. h producedWater) 3)
          (set-h (producedWater (+ (. h producedWater) 1))
                 (progressSlots 1))
          (keep-h))))
    (pollProgress
      (action pollProgress ()
        (if (> (. h progressSlots) 0)
          (set-h (observedWater (. h producedWater))
                 (progressSlots 0))
          (keep-h))))
    (step
      (action step ()
        (any submitHi submitLo cancelLo drainOne publishProgress pollProgress))))
  safety:
  '(and (<= (. h hiQueue) 2)
        (<= (. h loQueue) 2)
        (not (. h hiStarved))
        (= (. h zombieLo) 0)
        (<= (. h progressSlots) 1)
        (<= (. h observedWater) (. h producedWater)))
  traces:
  '((checkMailboxSafe
      (action checkMailboxSafe ()
        (all (assert (> (. h shedLoCount) 0))
             (assert (= (. h hiQueue) 0))
             (assert (= (. h zombieLo) 0))
             (assert (= (. h progressSlots) 0))
             (assert (= (. h observedWater) (. h producedWater)))
             (assert safety)
             (keep-h))))
    (checkMailboxViolated
      (action checkMailboxViolated ()
        (all (assert (or (. h hiStarved) (> (. h loQueue) 2) (> (. h zombieLo) 0)))
             (assert (not safety))
             (keep-h))))
    (priorityIsolationAndWatchTest
      (run priorityIsolationAndWatchTest
        (then init submitLo submitLo submitLo submitHi publishProgress publishProgress pollProgress drainOne drainOne drainOne checkMailboxSafe)))
    (sharedChannelPriorityInversionRefutedTest
      (run sharedChannelPriorityInversionRefutedTest
        (then init submitLo submitLo submitHiSharedChannel checkMailboxViolated)))
    (unboundedQueueGrowthRefutedTest
      (run unboundedQueueGrowthRefutedTest
        (then init submitLo submitLo submitLoUnbounded checkMailboxViolated)))
    (zombieSlotLeakRefutedTest
      (run zombieSlotLeakRefutedTest
        (then init submitLo cancelLoUncompacted checkMailboxViolated))))
  countermodels:
  (list SharedChannelPriorityInversionCountermodel
        UnboundedQueueGrowthCountermodel
        ZombieSlotLeakCountermodel)
  limits: "Finite 2-slot per-tier priority mailbox and 1-slot watch channel abstraction; verifies priority isolation under overload, bounded shedding, cancelled-job compaction, and monotonic watch progress, not OS thread scheduling.")

(.def (SharedChannelPriorityInversionCountermodel @ PriorityIsolatedBoundedMailboxModel)
  identity: 'engineering.concurrency.priority-isolated-bounded-mailbox.shared-channel-priority-inversion
  dropped-guard: 'isolate-priority-ingress
  step-action: "stepSharedChannelPriorityInversion"
  derive-from-transition: 'submitHi
  derive-action-name: 'submitHiSharedChannel
  expected-itf-predicate: "h.hiStarved == true")

(.def (UnboundedQueueGrowthCountermodel @ PriorityIsolatedBoundedMailboxModel)
  identity: 'engineering.concurrency.priority-isolated-bounded-mailbox.unbounded-queue-growth
  dropped-guard: 'bound-ingress-capacity
  step-action: "stepUnboundedQueueGrowth"
  derive-from-transition: 'submitLo
  derive-action-name: 'submitLoUnbounded
  expected-itf-predicate: "h.loQueue > 2")

(.def (ZombieSlotLeakCountermodel @ PriorityIsolatedBoundedMailboxModel)
  identity: 'engineering.concurrency.priority-isolated-bounded-mailbox.zombie-slot-leak
  dropped-guard: 'compact-cancelled-zombies
  step-action: "stepZombieSlotLeak"
  derive-from-transition: 'cancelLo
  derive-action-name: 'cancelLoUncompacted
  expected-itf-predicate: "h.zombieLo > 0")
