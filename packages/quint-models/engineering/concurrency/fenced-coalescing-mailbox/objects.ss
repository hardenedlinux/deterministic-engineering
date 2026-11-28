;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Generation-fenced coalescing async mailbox model.
;;; Co-located Yuanxu unit: single source of truth alongside FencedCoalescingMailbox.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export FencedCoalescingMailboxModel)

(.def (FencedCoalescingMailboxModel @ ThreatModel.)
  identity: 'engineering.concurrency.fenced-coalescing-mailbox
  family: 'engineering.concurrency.fenced-coalescing-mailbox
  title: "Generation-Fenced Coalescing Async Mailbox"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("M. Kleppmann (2016)"
     "How to do distributed locking — monotonic fencing tokens rejecting stale in-flight completions.")
    ("Reactive Streams Specification (2015)"
     "Bounded non-blocking backpressure and single-slot latest-value coalescing across async boundaries.")
    ("C. Hewitt, P. Bishop & R. Steiger (IJCAI 1973)"
     "Universal Modular ACTOR Formalism — bounded mailbox isolation for concurrent message dispatch."))
  quint-module: "concurrency_fenced_mailbox"
  quint-file: "FencedCoalescingMailbox.qnt"
  domain-dir: "engineering/concurrency/fenced-coalescing-mailbox"
  rules:
  '((mailbox-coalesced MAILBOX-COALESCE quint)
    (mailbox-epoch-fenced MAILBOX-FENCE quint))
  dependencies:
  '((MAILBOX-COALESCE source)
    (MAILBOX-COALESCE profile)
    (MAILBOX-COALESCE method)
    (MAILBOX-FENCE source)
    (MAILBOX-FENCE profile)
    (MAILBOX-FENCE method))
  invariant: "Pending mailbox depth never exceeds 1 via latest-wins coalescing, in-flight workers stay bounded, and committed UI state epoch never regresses behind the highest committed epoch (appliedEpoch == maxAppliedEpoch <= activeEpoch)."
  limits: "Finite 4-epoch single-slot coalescing mailbox abstraction; does not model OS timer jitter, multi-lane priority preemption, or payload serialization sizes.")
