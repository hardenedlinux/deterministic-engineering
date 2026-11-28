;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/gc/tricolor-write-barrier/objects
                 TricolorWriteBarrierModel)
        "../../../support/quint-model-qualification.ss")
(export tricolor-write-barrier-qualification-test)

(def tricolor-write-barrier-qualification-test
  (make-quint-model-qualification-suite "tricolor-write-barrier" TricolorWriteBarrierModel))
