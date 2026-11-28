;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/partial-order-delivery/objects
                 PartialOrderDeliveryModel)
        "../../../support/quint-model-qualification.ss")
(export partial-order-delivery-qualification-test)

(def partial-order-delivery-qualification-test
  (make-quint-model-qualification-suite "partial-order-delivery" PartialOrderDeliveryModel))
