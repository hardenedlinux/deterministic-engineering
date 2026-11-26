;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/wasm-sandbox-confinement/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export wasm-sandbox-confinement-qualification-test)

(def wasm-sandbox-confinement-qualification-test
  (make-quint-model-qualification-suite
    "wasm-sandbox-confinement"
    WasmSandboxConfinementModel
    (.get ThreatModelProfiles wasm-sandbox-confinement)))
