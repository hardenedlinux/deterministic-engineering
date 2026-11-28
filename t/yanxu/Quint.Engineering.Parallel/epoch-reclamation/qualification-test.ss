;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/parallel/epoch-reclamation/objects
                 EpochReclamationModel)
        "../../../support/quint-model-qualification.ss")
(export epoch-reclamation-qualification-test)

(def epoch-reclamation-qualification-test
  (make-quint-model-qualification-suite "epoch-reclamation" EpochReclamationModel))
