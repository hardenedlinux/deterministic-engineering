;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/lease-fencing-token/objects
                 LeaseFencingModel)
        "../../../support/quint-model-qualification.ss")
(export lease-fencing-token-qualification-test)

(def lease-fencing-token-qualification-test
  (make-quint-model-qualification-suite "lease-fencing-token" LeaseFencingModel))
