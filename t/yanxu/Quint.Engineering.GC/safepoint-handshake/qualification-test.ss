;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/gc/safepoint-handshake/objects
                 SafepointHandshakeModel)
        "../../../support/quint-model-qualification.ss")
(export safepoint-handshake-qualification-test)

(def safepoint-handshake-qualification-test
  (make-quint-model-qualification-suite "safepoint-handshake" SafepointHandshakeModel))
