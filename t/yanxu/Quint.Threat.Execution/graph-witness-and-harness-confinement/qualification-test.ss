;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/execution/graph-witness-and-harness-confinement/objects
                 GraphWitnessAndHarnessConfinementModel)
        "../../../support/quint-model-qualification.ss")
(export graph-witness-and-harness-confinement-qualification-test)

(def graph-witness-and-harness-confinement-qualification-test
  (make-quint-model-qualification-suite
    "graph-witness-and-harness-confinement"
    GraphWitnessAndHarnessConfinementModel))
