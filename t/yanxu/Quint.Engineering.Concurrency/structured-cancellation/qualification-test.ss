;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/structured-cancellation/objects
                 StructuredCancelModel)
        "../../../support/quint-model-qualification.ss")
(export structured-cancellation-qualification-test)

(def structured-cancellation-qualification-test
  (make-quint-model-qualification-suite "structured-cancellation" StructuredCancelModel))
