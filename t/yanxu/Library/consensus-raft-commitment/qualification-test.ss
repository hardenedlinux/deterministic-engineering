;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/consensus-raft-commitment/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export consensus-raft-commitment-qualification-test)

(def consensus-raft-commitment-qualification-test
  (make-quint-model-qualification-suite
    "consensus-raft-commitment"
    RaftLeaderCommitmentModel
    (.get ThreatModelProfiles consensus-raft-commitment)))
