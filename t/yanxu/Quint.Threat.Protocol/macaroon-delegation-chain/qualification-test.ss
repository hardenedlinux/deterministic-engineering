;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/protocol/macaroon-delegation-chain/objects
                 MacaroonDelegationModel)
        "../../../support/quint-model-qualification.ss")
(export macaroon-delegation-chain-qualification-test)

(def macaroon-delegation-chain-qualification-test
  (make-quint-model-qualification-suite "macaroon-delegation-chain" MacaroonDelegationModel))
