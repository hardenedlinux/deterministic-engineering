;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/microsegmentation-egress/objects
                 MicrosegmentationEgressModel)
        "../../../support/quint-model-qualification.ss")
(export microsegmentation-egress-qualification-test)

(def microsegmentation-egress-qualification-test
  (make-quint-model-qualification-suite "microsegmentation-egress" MicrosegmentationEgressModel))
