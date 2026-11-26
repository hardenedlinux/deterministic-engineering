;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/witness-epoch-reconfiguration/objects
                 WitnessEpochReconfigurationModel)
        "../../../support/quint-model-qualification.ss")
(export witness-epoch-reconfiguration-qualification-test)

(def witness-epoch-reconfiguration-qualification-test
  (make-quint-model-qualification-suite
    "witness-epoch-reconfiguration"
    WitnessEpochReconfigurationModel))
