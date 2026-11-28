;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/execution/effect-handoff/objects
                 EffectHandoffModel)
        "../../../support/quint-model-qualification.ss")
(export effect-handoff-qualification-test)

(def effect-handoff-qualification-test
  (make-quint-model-qualification-suite "effect-handoff" EffectHandoffModel))
