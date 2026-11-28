;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/execution/wasm-sandbox-confinement/objects
                 WasmSandboxConfinementModel)
        "../../../support/quint-model-qualification.ss")
(export wasm-sandbox-confinement-qualification-test)

(def wasm-sandbox-confinement-qualification-test
  (make-quint-model-qualification-suite "wasm-sandbox-confinement" WasmSandboxConfinementModel))
