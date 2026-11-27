;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/gc/gc-pacing-thrash-guard/objects
                 GcPacingThrashGuardModel)
        "../../../support/quint-model-qualification.ss")
(export gc-pacing-thrash-guard-qualification-test)

(def gc-pacing-thrash-guard-qualification-test
  (make-quint-model-qualification-suite "gc-pacing-thrash-guard" GcPacingThrashGuardModel))
