;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Broadcast lag snapshot-resync & coalesced streaming checkpoint flush model.
;;; Co-located Yuanxu unit: single source of truth alongside StreamLagResyncCoalescing.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export StreamLagResyncCoalescingModel)

(.def (StreamLagResyncCoalescingModel @ ThreatModel.)
  identity: 'engineering.concurrency.stream-lag-resync-coalescing
  family: 'engineering.concurrency.stream-lag-resync-coalescing
  title: "Broadcast Lag Snapshot-Resync & Coalesced Checkpoint Flush"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("Reactive Streams Specification (2015)"
     "Bounded non-blocking backpressure and demand-driven coalesced updates across async boundaries.")
    ("M. Welsh, D. Culler, E. Brewer (ACM SOSP 2001)"
     "SEDA: Well-Conditioned Internet Services — batching and graceful state resynchronization under consumer lag.")
    ("M. Rosenblum & J. K. Ousterhout (ACM TOCS 1992)"
     "The Design and Implementation of a Log-Structured File System — bounding write amplification via coalesced flushes."))
  quint-module: "concurrency_stream_lag_resync"
  quint-file: "StreamLagResyncCoalescing.qnt"
  domain-dir: "engineering/concurrency/stream-lag-resync-coalescing"
  rules:
  '((conc-lag-resync CONC-LAG-RESYNC quint)
    (conc-batch-flush CONC-BATCH-FLUSH quint))
  dependencies:
  '((CONC-LAG-RESYNC source)
    (CONC-LAG-RESYNC profile)
    (CONC-LAG-RESYNC method)
    (CONC-BATCH-FLUSH source)
    (CONC-BATCH-FLUSH profile)
    (CONC-BATCH-FLUSH method))
  invariant: "Lagged broadcast subscribers recover cleanly via generation-fenced full-snapshot resync instead of silently terminating the stream, and streaming projection persistence coalesces dirty tokens to prevent per-token write amplification."
  limits: "Finite 6-generation broadcast-lag and 2-token batch-flush abstraction; models snapshot resync continuity and write-amplification coalescing, not kernel TCP flow control or filesystem fsync latency.")
