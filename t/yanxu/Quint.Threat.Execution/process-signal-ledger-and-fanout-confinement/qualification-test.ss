;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/execution/process-signal-ledger-and-fanout-confinement/objects
                 ProcessSignalLedgerAndFanoutConfinementModel)
        "../../../support/quint-model-qualification.ss")
(export process-signal-ledger-and-fanout-confinement-qualification-test)

(def process-signal-ledger-and-fanout-confinement-qualification-test
  (make-quint-model-qualification-suite
    "process-signal-ledger-and-fanout-confinement"
    ProcessSignalLedgerAndFanoutConfinementModel))
