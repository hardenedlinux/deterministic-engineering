;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/unknown-effect-retry/objects
                 UnknownEffectRetryModel)
        "../../../support/quint-model-qualification.ss")
(export unknown-effect-retry-qualification-test)

(def unknown-effect-retry-qualification-test
  (make-quint-model-qualification-suite "unknown-effect-retry" UnknownEffectRetryModel))
