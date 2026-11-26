;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/process-tree-reclamation/objects
                 ProcessTreeReclamationModel)
        "../../../support/quint-model-qualification.ss")
(export process-tree-reclamation-qualification-test)

(def process-tree-reclamation-qualification-test
  (make-quint-model-qualification-suite "process-tree-reclamation" ProcessTreeReclamationModel))
