;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/ime-composition-focus-race/objects
                 ImeCompositionFocusRaceModel)
        "../../../support/quint-model-qualification.ss")
(export ime-composition-focus-race-qualification-test)

(def ime-composition-focus-race-qualification-test
  (make-quint-model-qualification-suite "ime-composition-focus-race" ImeCompositionFocusRaceModel))
