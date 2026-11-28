;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/singleflight-cancellation-safety/objects
                 SingleFlightCancellationSafetyModel)
        "../../../support/quint-model-qualification.ss")
(export singleflight-cancellation-safety-qualification-test)

(def singleflight-cancellation-safety-qualification-test
  (make-quint-model-qualification-suite "singleflight-cancellation-safety" SingleFlightCancellationSafetyModel))
