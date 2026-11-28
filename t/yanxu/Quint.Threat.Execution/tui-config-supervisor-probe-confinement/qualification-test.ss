;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/execution/tui-config-supervisor-probe-confinement/objects
                 TuiConfigSupervisorProbeConfinementModel)
        "../../../support/quint-model-qualification.ss")
(export tui-config-supervisor-probe-confinement-qualification-test)

(def tui-config-supervisor-probe-confinement-qualification-test
  (make-quint-model-qualification-suite
    "tui-config-supervisor-probe-confinement"
    TuiConfigSupervisorProbeConfinementModel))
