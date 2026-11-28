;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/geo-residency-sovereignty/objects
                 GeoResidencySovereigntyModel)
        "../../../support/quint-model-qualification.ss")
(export geo-residency-sovereignty-qualification-test)

(def geo-residency-sovereignty-qualification-test
  (make-quint-model-qualification-suite
    "geo-residency-sovereignty"
    GeoResidencySovereigntyModel))
