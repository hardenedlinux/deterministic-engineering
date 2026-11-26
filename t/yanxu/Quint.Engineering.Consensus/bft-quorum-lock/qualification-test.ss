;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/consensus/bft-quorum-lock/objects
                 BftQuorumLockModel)
        "../../../support/quint-model-qualification.ss")
(export bft-quorum-lock-qualification-test)

(def bft-quorum-lock-qualification-test
  (make-quint-model-qualification-suite "bft-quorum-lock" BftQuorumLockModel))
