;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Slow-consumer bounded fan-out buffer & eviction-drain reclamation model.
;;; Co-located Yuanxu unit: single source of truth alongside SlowConsumerEviction.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export SlowConsumerEvictionModel
        UnboundedSlowQueueCountermodel
        EvictedBufferLeakCountermodel)

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
  quint-imports: '()
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
  parameters: '()
  state:
  '((slowConnected "bool" "true")
    (slowBuf "int" "0")
    (fastDelivered "int" "0")
    (orphanedBuf "int" "0"))
  guards:
  '((slow-consumer-evict-cap (< (. h slowBuf) 2))
    (evicted-buffer-drain 0))
  transitions:
  '((publishFrame
      (action publishFrame ()
        (if (and (< (. h fastDelivered) 4) (not (. h slowConnected)))
          (set-h (fastDelivered (+ (. h fastDelivered) 1)))
          (if (and (< (. h fastDelivered) 4)
                   (. h slowConnected)
                   (< (. h slowBuf) 3)
                   (guard slow-consumer-evict-cap (< (. h slowBuf) 2)))
            (set-h (slowBuf (+ (. h slowBuf) 1))
                   (fastDelivered (+ (. h fastDelivered) 1)))
            (keep-h)))))
    (slowConsumeOne
      (action slowConsumeOne ()
        (if (and (. h slowConnected) (> (. h slowBuf) 0))
          (set-h (slowBuf (- (. h slowBuf) 1)))
          (keep-h))))
    (evictSlowConsumer
      (action evictSlowConsumer ()
        (if (and (. h slowConnected) (>= (. h slowBuf) 2))
          (set-h (slowConnected #f)
                 (slowBuf 0)
                 (orphanedBuf (guard evicted-buffer-drain 0 (. h slowBuf))))
          (keep-h))))
    (reconnectSlow
      (action reconnectSlow ()
        (if (and (not (. h slowConnected))
                 (= (. h orphanedBuf) 0)
                 (< (. h fastDelivered) 4))
          (set-h (slowConnected #t))
          (keep-h))))
    (step
      (action step ()
        (any publishFrame slowConsumeOne evictSlowConsumer reconnectSlow))))
  safety:
  '(and (<= (. h slowBuf) 2)
        (= (. h orphanedBuf) 0)
        (or (. h slowConnected) (= (. h slowBuf) 0)))
  traces:
  '((checkIsolatedHealthy
      (action checkIsolatedHealthy ()
        (all (assert (not (. h slowConnected)))
             (assert (= (. h slowBuf) 0))
             (assert (= (. h orphanedBuf) 0))
             (assert (> (. h fastDelivered) 2))
             (assert safety)
             (keep-h))))
    (checkSlowViolation
      (action checkSlowViolation ()
        (all (assert (or (> (. h slowBuf) 2) (> (. h orphanedBuf) 0)))
             (assert (not safety))
             (keep-h))))
    (slowEvictionPreservesFastProgressTest
      (run slowEvictionPreservesFastProgressTest
        (then init publishFrame publishFrame evictSlowConsumer publishFrame checkIsolatedHealthy)))
    (unboundedSlowQueueRefutedTest
      (run unboundedSlowQueueRefutedTest
        (then init publishFrame publishFrame publishFrameUnbounded checkSlowViolation)))
    (evictedBufferLeakRefutedTest
      (run evictedBufferLeakRefutedTest
        (then init publishFrame publishFrame evictSlowConsumerLeaky checkSlowViolation))))
  countermodels: (list UnboundedSlowQueueCountermodel EvictedBufferLeakCountermodel)
  limits: "Finite 2-frame slow-subscriber fan-out abstraction; models per-subscriber bounded buffering and eviction cleanup, not kernel TCP send-window dynamics or OS socket teardown latency.")

(.def (UnboundedSlowQueueCountermodel @ SlowConsumerEvictionModel)
  identity: 'engineering.concurrency.slow-consumer-eviction.unbounded-slow-queue
  dropped-guard: 'slow-consumer-evict-cap
  step-action: "stepUnboundedSlowQueue"
  derive-from-transition: 'publishFrame
  derive-action-name: 'publishFrameUnbounded
  expected-itf-predicate: "h.slowBuf > 2")

(.def (EvictedBufferLeakCountermodel @ SlowConsumerEvictionModel)
  identity: 'engineering.concurrency.slow-consumer-eviction.evicted-buffer-leak
  dropped-guard: 'evicted-buffer-drain
  step-action: "stepEvictedBufferLeak"
  derive-from-transition: 'evictSlowConsumer
  derive-action-name: 'evictSlowConsumerLeaky
  expected-itf-predicate: "h.orphanedBuf > 0")
