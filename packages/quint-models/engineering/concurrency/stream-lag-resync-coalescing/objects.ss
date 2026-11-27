;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Broadcast lag snapshot-resync & coalesced streaming checkpoint flush model.
;;; Co-located Yuanxu unit: single source of truth alongside StreamLagResyncCoalescing.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export StreamLagResyncCoalescingModel
        SilentLagDisconnectCountermodel
        PerTokenWriteAmpCountermodel)

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
  quint-imports: '()
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
  parameters: '()
  state:
  '((serverGen "int" "0")
    (clientGen "int" "0")
    (lagged "bool" "false")
    (streamAlive "bool" "true")
    (dirtyBatch "int" "0")
    (flushedBatches "int" "0")
    (uncoalescedFlushes "int" "0"))
  guards:
  '((resync-snapshot-on-lag (. h streamAlive))
    (coalesce-batch-flush (>= (. h dirtyBatch) 2)))
  transitions:
  '((emitDelta
      (action emitDelta ()
        (if (and (< (. h serverGen) 6) (< (. h dirtyBatch) 2))
          (set-h (serverGen (+ (. h serverGen) 1))
                 (dirtyBatch (+ (. h dirtyBatch) 1))
                 (lagged (or (. h lagged) (> (- (+ (. h serverGen) 1) (. h clientGen)) 2))))
          (keep-h))))
    (consumeDelta
      (action consumeDelta ()
        (if (and (. h streamAlive) (not (. h lagged)) (< (. h clientGen) (. h serverGen)))
          (set-h (clientGen (+ (. h clientGen) 1)))
          (keep-h))))
    (resyncOnLag
      (action resyncOnLag ()
        (if (and (. h streamAlive) (. h lagged))
          (set-h (clientGen (. h serverGen))
                 (lagged #f)
                 (streamAlive (guard resync-snapshot-on-lag (. h streamAlive) #f)))
          (keep-h))))
    (flushCheckpoint
      (action flushCheckpoint ()
        (if (and (> (. h dirtyBatch) 0)
                 (guard coalesce-batch-flush (>= (. h dirtyBatch) 2)))
          (set-h (dirtyBatch 0)
                 (flushedBatches (+ (. h flushedBatches) 1))
                 (uncoalescedFlushes (if (< (. h dirtyBatch) 2)
                                       (+ (. h uncoalescedFlushes) 1)
                                       (. h uncoalescedFlushes))))
          (keep-h))))
    (step
      (action step ()
        (any emitDelta consumeDelta resyncOnLag flushCheckpoint))))
  safety:
  '(and (. h streamAlive)
        (<= (. h clientGen) (. h serverGen))
        (<= (. h dirtyBatch) 2)
        (= (. h uncoalescedFlushes) 0)
        (or (. h lagged) (<= (- (. h serverGen) (. h clientGen)) 2)))
  traces:
  '((checkResyncHealthy
      (action checkResyncHealthy ()
        (all (assert (. h streamAlive))
             (assert (not (. h lagged)))
             (assert (= (. h clientGen) (. h serverGen)))
             (assert (= (. h uncoalescedFlushes) 0))
             (assert (> (. h flushedBatches) 0))
             (assert safety)
             (keep-h))))
    (checkStreamViolation
      (action checkStreamViolation ()
        (all (assert (or (not (. h streamAlive)) (> (. h uncoalescedFlushes) 0)))
             (assert (not safety))
             (keep-h))))
    (lagResyncAndCoalescedFlushTest
      (run lagResyncAndCoalescedFlushTest
        (then init emitDelta emitDelta flushCheckpoint emitDelta resyncOnLag checkResyncHealthy)))
    (silentLagDisconnectRefutedTest
      (run silentLagDisconnectRefutedTest
        (then init emitDelta emitDelta flushCheckpoint emitDelta resyncOnLagDropStream checkStreamViolation)))
    (perTokenWriteAmpRefutedTest
      (run perTokenWriteAmpRefutedTest
        (then init emitDelta flushCheckpointPerToken checkStreamViolation))))
  countermodels: (list SilentLagDisconnectCountermodel PerTokenWriteAmpCountermodel)
  limits: "Finite 6-generation broadcast-lag and 2-token batch-flush abstraction; models snapshot resync continuity and write-amplification coalescing, not kernel TCP flow control or filesystem fsync latency.")

(.def (SilentLagDisconnectCountermodel @ StreamLagResyncCoalescingModel)
  identity: 'engineering.concurrency.stream-lag-resync-coalescing.silent-lag-disconnect
  dropped-guard: 'resync-snapshot-on-lag
  step-action: "stepSilentLagDisconnect"
  derive-from-transition: 'resyncOnLag
  derive-action-name: 'resyncOnLagDropStream
  expected-itf-predicate: "h.streamAlive == false")

(.def (PerTokenWriteAmpCountermodel @ StreamLagResyncCoalescingModel)
  identity: 'engineering.concurrency.stream-lag-resync-coalescing.per-token-write-amp
  dropped-guard: 'coalesce-batch-flush
  step-action: "stepPerTokenWriteAmp"
  derive-from-transition: 'flushCheckpoint
  derive-action-name: 'flushCheckpointPerToken
  expected-itf-predicate: "h.uncoalescedFlushes > 0")
