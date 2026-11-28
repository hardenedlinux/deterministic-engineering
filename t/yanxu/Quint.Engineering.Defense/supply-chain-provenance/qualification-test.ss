;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/supply-chain-provenance/objects
                 SupplyChainProvenanceModel)
        "../../../support/quint-model-qualification.ss")
(export supply-chain-provenance-qualification-test)

(def supply-chain-provenance-qualification-test
  (make-quint-model-qualification-suite
    "supply-chain-provenance"
    SupplyChainProvenanceModel))
