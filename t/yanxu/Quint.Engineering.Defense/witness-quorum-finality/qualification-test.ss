;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/witness-quorum-finality/objects
                 WitnessQuorumFinalityModel)
        "../../../support/quint-model-qualification.ss")
(export witness-quorum-finality-qualification-test)

(def witness-quorum-finality-qualification-test
  (make-quint-model-qualification-suite "witness-quorum-finality" WitnessQuorumFinalityModel))
