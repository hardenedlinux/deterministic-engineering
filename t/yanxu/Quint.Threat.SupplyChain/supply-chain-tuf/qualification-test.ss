;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/supply-chain/supply-chain-tuf/objects
                 SupplyChainTufModel)
        "../../../support/quint-model-qualification.ss")
(export supply-chain-tuf-qualification-test)

(def supply-chain-tuf-qualification-test
  (make-quint-model-qualification-suite "supply-chain-tuf" SupplyChainTufModel))
