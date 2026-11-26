;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/durable-agent-persistence/objects
                 DurableAgentPersistenceModel)
        "../../../support/quint-model-qualification.ss")
(export durable-agent-persistence-qualification-test)

(def durable-agent-persistence-qualification-test
  (make-quint-model-qualification-suite "durable-agent-persistence" DurableAgentPersistenceModel))
