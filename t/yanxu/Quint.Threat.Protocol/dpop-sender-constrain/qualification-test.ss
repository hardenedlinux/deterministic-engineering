;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/protocol/dpop-sender-constrain/objects
                 DpopSenderConstrainModel)
        "../../../support/quint-model-qualification.ss")
(export dpop-sender-constrain-qualification-test)

(def dpop-sender-constrain-qualification-test
  (make-quint-model-qualification-suite "dpop-sender-constrain" DpopSenderConstrainModel))
