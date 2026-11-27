;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/zk-selective-disclosure/objects
                 ZkSelectiveDisclosureModel)
        "../../../support/quint-model-qualification.ss")
(export zk-selective-disclosure-qualification-test)

(def zk-selective-disclosure-qualification-test
  (make-quint-model-qualification-suite
    "zk-selective-disclosure"
    ZkSelectiveDisclosureModel))
