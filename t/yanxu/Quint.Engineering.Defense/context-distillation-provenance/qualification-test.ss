;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/context-distillation-provenance/objects
                 ContextDistillationProvenanceModel)
        "../../../support/quint-model-qualification.ss")
(export context-distillation-provenance-qualification-test)

(def context-distillation-provenance-qualification-test
  (make-quint-model-qualification-suite
    "context-distillation-provenance"
    ContextDistillationProvenanceModel))
