;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Bidirectional IPC / gRPC half-open stream retirement, monotonic epoch
;;; frame fencing, and idempotent replay deduplication model (SM12).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export IpcHalfOpenReconnectIdempotencyModel
        HalfOpenStreamLeakCountermodel
        DuplicateReplayEffectCountermodel
        StaleEpochFrameInterleaveCountermodel)

(.def (IpcHalfOpenReconnectIdempotencyModel @ ThreatModel.)
  identity: 'engineering.concurrency.ipc-half-open-reconnect-idempotency
  family: 'engineering.concurrency.ipc-half-open-reconnect-idempotency
  title: "IPC Half-Open Stream Retirement, Epoch Fencing & Idempotent Replay"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("J. Saltzer, D. Reed & D. Clark (ACM TOCS 1984)"
     "End-to-End Arguments in System Design — transport retries require application-level idempotency keys to avoid duplicate mutations.")
    ("M. Kleppmann (2016)"
     "How to Do Distributed Locking — monotonic fencing tokens reject delayed frames from superseded epochs.")
    ("L. Lamport (ACM TOPLAS 1978)"
     "Time, Clocks, and the Ordering of Events in a Distributed System — monotonic epoch ordering across asynchronous channels."))
  quint-module: "concurrency_ipc_half_open_reconnect_idempotency"
  quint-file: "IpcHalfOpenReconnectIdempotency.qnt"
  domain-dir: "engineering/concurrency/ipc-half-open-reconnect-idempotency"
  quint-imports: '()
  rules:
  '((conc-ipc-retire-half-open CONC-IPC-RETIRE-HALF-OPEN quint)
    (conc-ipc-idempotent-dedup CONC-IPC-IDEMPOTENT-DEDUP quint)
    (conc-ipc-epoch-fence CONC-IPC-EPOCH-FENCE quint))
  dependencies:
  '((CONC-IPC-RETIRE-HALF-OPEN source)
    (CONC-IPC-RETIRE-HALF-OPEN profile)
    (CONC-IPC-RETIRE-HALF-OPEN method)
    (CONC-IPC-IDEMPOTENT-DEDUP source)
    (CONC-IPC-IDEMPOTENT-DEDUP profile)
    (CONC-IPC-IDEMPOTENT-DEDUP method)
    (CONC-IPC-EPOCH-FENCE source)
    (CONC-IPC-EPOCH-FENCE profile)
    (CONC-IPC-EPOCH-FENCE method))
  invariant: "Reconnecting a half-open IPC/gRPC stream retires the superseded stream so activeStreams stays bounded at 1, replaying a committed idempotency key produces zero duplicate side effects, and late frames from superseded session epochs are fenced and dropped."
  parameters: '()
  state:
  '((sessionEpoch "int" "1")
    (activeStreams "int" "1")
    (inFlightKey "int" "0")
    (committedKey1 "bool" "false")
    (duplicateEffects "int" "0")
    (staleFramesApplied "int" "0")
    (reconnectCount "int" "0"))
  guards:
  '((retire-stale-stream-on-reconnect true)
    (dedup-idempotent-replay true)
    (fence-stale-epoch-frame true))
  transitions:
  '((sendRequest
      (action sendRequest ()
        (if (= (. h inFlightKey) 0)
          (set-h (inFlightKey 1))
          (keep-h))))
    (commitRequest
      (action commitRequest ()
        (if (= (. h inFlightKey) 1)
          (if (not (. h committedKey1))
            (set-h (committedKey1 true)
                   (inFlightKey 0))
            (if (guard dedup-idempotent-replay true false)
              (set-h (inFlightKey 0))
              (set-h (duplicateEffects (+ (. h duplicateEffects) 1))
                     (inFlightKey 0))))
          (keep-h))))
    (reconnectHalfOpen
      (action reconnectHalfOpen ()
        (if (< (. h reconnectCount) 3)
          (if (guard retire-stale-stream-on-reconnect true false)
            (set-h (sessionEpoch (+ (. h sessionEpoch) 1))
                   (activeStreams 1)
                   (reconnectCount (+ (. h reconnectCount) 1)))
            (set-h (sessionEpoch (+ (. h sessionEpoch) 1))
                   (activeStreams (+ (. h activeStreams) 1))
                   (reconnectCount (+ (. h reconnectCount) 1))))
          (keep-h))))
    (receiveStaleFrame
      (action receiveStaleFrame ()
        (if (> (. h sessionEpoch) 1)
          (if (guard fence-stale-epoch-frame true false)
            (keep-h)
            (set-h (staleFramesApplied (+ (. h staleFramesApplied) 1))))
          (keep-h))))
    (step
      (action step ()
        (any sendRequest commitRequest reconnectHalfOpen receiveStaleFrame))))
  safety:
  '(and (<= (. h activeStreams) 1)
        (= (. h duplicateEffects) 0)
        (= (. h staleFramesApplied) 0)
        (>= (. h sessionEpoch) 1))
  traces:
  '((checkIpcSafe
      (action checkIpcSafe ()
        (all (assert (. h committedKey1))
             (assert (> (. h reconnectCount) 0))
             (assert (= (. h activeStreams) 1))
             (assert (= (. h duplicateEffects) 0))
             (assert (= (. h staleFramesApplied) 0))
             (assert safety)
             (keep-h))))
    (checkIpcViolated
      (action checkIpcViolated ()
        (all (assert (or (> (. h activeStreams) 1)
                         (> (. h duplicateEffects) 0)
                         (> (. h staleFramesApplied) 0)))
             (assert (not safety))
             (keep-h))))
    (reconnectIdempotentSafeTest
      (run reconnectIdempotentSafeTest
        (then init sendRequest commitRequest reconnectHalfOpen sendRequest commitRequest receiveStaleFrame checkIpcSafe)))
    (halfOpenStreamLeakRefutedTest
      (run halfOpenStreamLeakRefutedTest
        (then init reconnectHalfOpenLeak checkIpcViolated)))
    (duplicateReplayRefutedTest
      (run duplicateReplayRefutedTest
        (then init sendRequest commitRequest sendRequest commitRequestDuplicate checkIpcViolated)))
    (staleFrameInterleaveRefutedTest
      (run staleFrameInterleaveRefutedTest
        (then init reconnectHalfOpen receiveStaleFrameUnfenced checkIpcViolated))))
  countermodels:
  (list HalfOpenStreamLeakCountermodel
        DuplicateReplayEffectCountermodel
        StaleEpochFrameInterleaveCountermodel)
  limits: "Finite 3-reconnect, single-key idempotency and epoch-fencing abstraction; verifies stream retirement, replay deduplication, and stale-frame rejection across half-open drops, not TLS handshake or TCP congestion control.")

(.def (HalfOpenStreamLeakCountermodel @ IpcHalfOpenReconnectIdempotencyModel)
  identity: 'engineering.concurrency.ipc-half-open-reconnect-idempotency.half-open-stream-leak
  dropped-guard: 'retire-stale-stream-on-reconnect
  step-action: "stepHalfOpenStreamLeak"
  derive-from-transition: 'reconnectHalfOpen
  derive-action-name: 'reconnectHalfOpenLeak
  expected-itf-predicate: "h.activeStreams > 1")

(.def (DuplicateReplayEffectCountermodel @ IpcHalfOpenReconnectIdempotencyModel)
  identity: 'engineering.concurrency.ipc-half-open-reconnect-idempotency.duplicate-replay-effect
  dropped-guard: 'dedup-idempotent-replay
  step-action: "stepDuplicateReplayEffect"
  derive-from-transition: 'commitRequest
  derive-action-name: 'commitRequestDuplicate
  expected-itf-predicate: "h.duplicateEffects > 0")

(.def (StaleEpochFrameInterleaveCountermodel @ IpcHalfOpenReconnectIdempotencyModel)
  identity: 'engineering.concurrency.ipc-half-open-reconnect-idempotency.stale-epoch-frame-interleave
  dropped-guard: 'fence-stale-epoch-frame
  step-action: "stepStaleEpochFrameInterleave"
  derive-from-transition: 'receiveStaleFrame
  derive-action-name: 'receiveStaleFrameUnfenced
  expected-itf-predicate: "h.staleFramesApplied > 0")
