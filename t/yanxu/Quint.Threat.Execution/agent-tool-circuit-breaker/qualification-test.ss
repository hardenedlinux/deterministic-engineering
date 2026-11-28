;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/execution/agent-tool-circuit-breaker/objects
                 AgentToolCircuitBreakerModel)
        "../../../support/quint-model-qualification.ss")
(export agent-tool-circuit-breaker-qualification-test)

(def agent-tool-circuit-breaker-qualification-test
  (make-quint-model-qualification-suite "agent-tool-circuit-breaker" AgentToolCircuitBreakerModel))
