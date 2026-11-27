;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/quiescence-resource-drain/objects
                 QuiescenceResourceDrainModel)
        "../../../support/quint-model-qualification.ss")
(export quiescence-resource-drain-qualification-test)

(def quiescence-resource-drain-qualification-test
  (make-quint-model-qualification-suite "quiescence-resource-drain" QuiescenceResourceDrainModel))
