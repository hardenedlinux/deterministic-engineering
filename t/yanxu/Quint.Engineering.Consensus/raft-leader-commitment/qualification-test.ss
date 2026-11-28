;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/consensus/raft-leader-commitment/objects
                 RaftLeaderCommitmentModel)
        "../../../support/quint-model-qualification.ss")
(export raft-leader-commitment-qualification-test)

(def raft-leader-commitment-qualification-test
  (make-quint-model-qualification-suite "raft-leader-commitment" RaftLeaderCommitmentModel))
