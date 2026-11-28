;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/supply-chain/transparency-log-gossip/objects
                 TransparencyLogGossipModel)
        "../../../support/quint-model-qualification.ss")
(export transparency-log-gossip-qualification-test)

(def transparency-log-gossip-qualification-test
  (make-quint-model-qualification-suite "transparency-log-gossip" TransparencyLogGossipModel))
