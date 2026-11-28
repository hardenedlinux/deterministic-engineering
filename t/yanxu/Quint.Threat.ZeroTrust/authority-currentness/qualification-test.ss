;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel)
        "../../../support/quint-model-qualification.ss")
(export authority-currentness-qualification-test)

(def authority-currentness-qualification-test
  (make-quint-model-qualification-suite "authority-currentness" AuthorityCurrentnessModel))
