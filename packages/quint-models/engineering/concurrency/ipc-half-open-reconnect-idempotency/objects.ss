;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Bidirectional IPC / gRPC half-open stream retirement, monotonic epoch
;;; frame fencing, and idempotent replay deduplication model (SM12).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export IpcHalfOpenReconnectIdempotencyModel)

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
  limits: "Finite 3-reconnect, single-key idempotency and epoch-fencing abstraction; verifies stream retirement, replay deduplication, and stale-frame rejection across half-open drops, not TLS handshake or TCP congestion control.")
