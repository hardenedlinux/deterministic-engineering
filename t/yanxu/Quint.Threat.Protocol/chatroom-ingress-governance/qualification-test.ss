;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/protocol/chatroom-ingress-governance/objects
                 ChatroomIngressGovernanceModel)
        "../../../support/quint-model-qualification.ss")
(export chatroom-ingress-governance-qualification-test)

(def chatroom-ingress-governance-qualification-test
  (make-quint-model-qualification-suite "chatroom-ingress-governance" ChatroomIngressGovernanceModel))
