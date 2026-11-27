;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Metastable overload failure, retry-budget amplification & load-shedding recovery model.
;;; Co-located Yuanxu unit: single source of truth alongside MetastableRetryCollapse.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export MetastableRetryCollapseModel
        NoLoadShedCountermodel
        UnboundedRetryStormCountermodel)

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
  quint-imports: '()
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
  parameters: '()
  state:
  '((congested "bool" "false")
    (triggerCleared "bool" "false")
    (queueDepth "int" "0")
    (retriesPending "int" "0")
    (shedCount "int" "0"))
  guards:
  '((overload-admission-shed (and (not (. h congested)) (< (. h queueDepth) 2)))
    (retry-budget-cap (and (< (. h retriesPending) 1) (< (. h queueDepth) 2))))
  transitions:
  '((admitFresh
      (action admitFresh ()
        (if (and (< (. h queueDepth) 3)
                 (< (. h shedCount) 3)
                 (guard overload-admission-shed (and (not (. h congested)) (< (. h queueDepth) 2))))
          (set-h (queueDepth (+ (. h queueDepth) 1)))
          (if (and (< (. h queueDepth) 3) (< (. h shedCount) 3))
            (set-h (shedCount (+ (. h shedCount) 1)))
            (keep-h)))))
    (triggerCongestion
      (action triggerCongestion ()
        (if (not (. h congested))
          (set-h (congested #t)
                 (triggerCleared #f))
          (keep-h))))
    (timeoutAndRetry
      (action timeoutAndRetry ()
        (if (and (. h congested)
                 (> (. h queueDepth) 0)
                 (< (. h queueDepth) 4)
                 (< (. h shedCount) 3)
                 (guard retry-budget-cap (and (< (. h retriesPending) 1) (< (. h queueDepth) 2))))
          (set-h (queueDepth (+ (. h queueDepth) 1))
                 (retriesPending (+ (. h retriesPending) 1)))
          (if (and (. h congested) (> (. h queueDepth) 0) (< (. h shedCount) 3))
            (set-h (shedCount (+ (. h shedCount) 1)))
            (keep-h)))))
    (clearTrigger
      (action clearTrigger ()
        (if (and (. h congested) (not (. h triggerCleared)))
          (set-h (triggerCleared #t))
          (keep-h))))
    (drainNormal
      (action drainNormal ()
        (if (and (> (. h queueDepth) 0)
                 (or (not (. h congested)) (. h triggerCleared)))
          (set-h (queueDepth (- (. h queueDepth) 1))
                 (retriesPending (if (> (. h retriesPending) 0) (- (. h retriesPending) 1) 0))
                 (congested (if (= (. h queueDepth) 1) #f (. h congested))))
          (keep-h))))
    (step
      (action step ()
        (any admitFresh triggerCongestion timeoutAndRetry clearTrigger drainNormal))))
  safety:
  '(and (<= (. h queueDepth) 2)
        (<= (. h retriesPending) 1)
        (<= (. h retriesPending) (. h queueDepth)))
  traces:
  '((checkRecovered
      (action checkRecovered ()
        (all (assert (not (. h congested)))
             (assert (= (. h queueDepth) 0))
             (assert (= (. h retriesPending) 0))
             (assert safety)
             (keep-h))))
    (checkOverloadCollapse
      (action checkOverloadCollapse ()
        (all (assert (or (> (. h queueDepth) 2) (> (. h retriesPending) 1)))
             (assert (not safety))
             (keep-h))))
    (boundedOverloadRecoveryTest
      (run boundedOverloadRecoveryTest
        (then init admitFresh triggerCongestion timeoutAndRetry admitFresh clearTrigger drainNormal drainNormal checkRecovered)))
    (noLoadShedRefutedTest
      (run noLoadShedRefutedTest
        (then init admitFresh admitFresh admitFreshUnchecked checkOverloadCollapse)))
    (unboundedRetryStormRefutedTest
      (run unboundedRetryStormRefutedTest
        (then init admitFresh triggerCongestion timeoutAndRetryUnchecked timeoutAndRetryUnchecked checkOverloadCollapse))))
  countermodels: (list NoLoadShedCountermodel UnboundedRetryStormCountermodel)
  limits: "Finite single-stage queue and retry-budget abstraction (queue cap=2, retry budget=1); models overload amplification and recovery bounds, not continuous service-time distributions or multi-hop network propagation delays.")

(.def (NoLoadShedCountermodel @ MetastableRetryCollapseModel)
  identity: 'engineering.concurrency.metastable-retry-collapse.no-load-shed
  dropped-guard: 'overload-admission-shed
  step-action: "stepNoLoadShed"
  derive-from-transition: 'admitFresh
  derive-action-name: 'admitFreshUnchecked
  expected-itf-predicate: "h.queueDepth > 2")

(.def (UnboundedRetryStormCountermodel @ MetastableRetryCollapseModel)
  identity: 'engineering.concurrency.metastable-retry-collapse.unbounded-retry-storm
  dropped-guard: 'retry-budget-cap
  step-action: "stepUnboundedRetryStorm"
  derive-from-transition: 'timeoutAndRetry
  derive-action-name: 'timeoutAndRetryUnchecked
  expected-itf-predicate: "h.retriesPending > 1 or h.queueDepth > 2")
