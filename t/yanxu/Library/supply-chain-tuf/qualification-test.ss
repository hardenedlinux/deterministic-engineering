;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/supply-chain-tuf/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export supply-chain-tuf-qualification-test)

(def supply-chain-tuf-qualification-test
  (make-quint-model-qualification-suite
    "supply-chain-tuf"
    SupplyChainTufModel
    (.get ThreatModelProfiles supply-chain-tuf)))
