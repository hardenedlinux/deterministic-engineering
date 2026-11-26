;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/identity/delegated-agent-authz/objects
                 DelegatedAgentAuthzModel)
        "../../../support/quint-model-qualification.ss")
(export delegated-agent-authz-qualification-test)

(def delegated-agent-authz-qualification-test
  (make-quint-model-qualification-suite "delegated-agent-authz" DelegatedAgentAuthzModel))
