;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/execution/telemetry-watchdog-and-deck-vm-confinement/objects
                 TelemetryWatchdogAndDeckVmConfinementModel)
        "../../../support/quint-model-qualification.ss")
(export telemetry-watchdog-and-deck-vm-confinement-qualification-test)

(def telemetry-watchdog-and-deck-vm-confinement-qualification-test
  (make-quint-model-qualification-suite
    "telemetry-watchdog-and-deck-vm-confinement"
    TelemetryWatchdogAndDeckVmConfinementModel))
