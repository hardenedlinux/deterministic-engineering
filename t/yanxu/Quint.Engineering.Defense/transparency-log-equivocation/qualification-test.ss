;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/transparency-log-equivocation/objects
                 TransparencyLogEquivocationModel)
        "../../../support/quint-model-qualification.ss")
(export transparency-log-equivocation-qualification-test)

(def transparency-log-equivocation-qualification-test
  (make-quint-model-qualification-suite "transparency-log-equivocation" TransparencyLogEquivocationModel))
