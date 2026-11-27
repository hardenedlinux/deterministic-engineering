;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/ipc-half-open-reconnect-idempotency/objects
                 IpcHalfOpenReconnectIdempotencyModel)
        "../../../support/quint-model-qualification.ss")
(export ipc-half-open-reconnect-idempotency-qualification-test)

(def ipc-half-open-reconnect-idempotency-qualification-test
  (make-quint-model-qualification-suite "ipc-half-open-reconnect-idempotency" IpcHalfOpenReconnectIdempotencyModel))
