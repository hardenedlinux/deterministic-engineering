;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/tool-sandbox-rpc-boundary/objects
                 ToolSandboxRpcBoundaryModel)
        "../../../support/quint-model-qualification.ss")
(export tool-sandbox-rpc-boundary-qualification-test)

(def tool-sandbox-rpc-boundary-qualification-test
  (make-quint-model-qualification-suite
    "tool-sandbox-rpc-boundary"
    ToolSandboxRpcBoundaryModel))
