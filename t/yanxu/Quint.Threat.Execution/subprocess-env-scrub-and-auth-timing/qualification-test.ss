;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/execution/subprocess-env-scrub-and-auth-timing/objects
                 SubprocessEnvScrubAndAuthTimingModel)
        "../../../support/quint-model-qualification.ss")
(export subprocess-env-scrub-and-auth-timing-qualification-test)

(def subprocess-env-scrub-and-auth-timing-qualification-test
  (make-quint-model-qualification-suite
    "subprocess-env-scrub-and-auth-timing"
    SubprocessEnvScrubAndAuthTimingModel))
