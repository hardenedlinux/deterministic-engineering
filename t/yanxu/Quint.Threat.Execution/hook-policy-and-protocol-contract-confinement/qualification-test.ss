;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/execution/hook-policy-and-protocol-contract-confinement/objects
                 HookPolicyAndProtocolContractConfinementModel)
        "../../../support/quint-model-qualification.ss")
(export hook-policy-and-protocol-contract-confinement-qualification-test)

(def hook-policy-and-protocol-contract-confinement-qualification-test
  (make-quint-model-qualification-suite
    "hook-policy-and-protocol-contract-confinement"
    HookPolicyAndProtocolContractConfinementModel))
