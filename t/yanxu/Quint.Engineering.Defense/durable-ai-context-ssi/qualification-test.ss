;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/durable-ai-context-ssi/objects
                 DurableAiContextSsiModel)
        "../../../support/quint-model-qualification.ss")
(export durable-ai-context-ssi-qualification-test)

(def durable-ai-context-ssi-qualification-test
  (make-quint-model-qualification-suite "durable-ai-context-ssi" DurableAiContextSsiModel))
