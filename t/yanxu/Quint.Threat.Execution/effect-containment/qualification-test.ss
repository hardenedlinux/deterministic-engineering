;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/execution/effect-containment/objects
                 EffectContainmentModel)
        "../../../support/quint-model-qualification.ss")
(export effect-containment-qualification-test)

(def effect-containment-qualification-test
  (make-quint-model-qualification-suite "effect-containment" EffectContainmentModel))
