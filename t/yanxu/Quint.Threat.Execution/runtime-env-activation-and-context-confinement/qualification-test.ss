;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/execution/runtime-env-activation-and-context-confinement/objects
                 RuntimeEnvActivationAndContextConfinementModel)
        "../../../support/quint-model-qualification.ss")
(export runtime-env-activation-and-context-confinement-qualification-test)

(def runtime-env-activation-and-context-confinement-qualification-test
  (make-quint-model-qualification-suite
    "runtime-env-activation-and-context-confinement"
    RuntimeEnvActivationAndContextConfinementModel))
