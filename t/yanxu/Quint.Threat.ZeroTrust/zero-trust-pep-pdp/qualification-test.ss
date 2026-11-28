;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/zero-trust-pep-pdp/objects
                 ZeroTrustPepPdpModel)
        "../../../support/quint-model-qualification.ss")
(export zero-trust-pep-pdp-qualification-test)

(def zero-trust-pep-pdp-qualification-test
  (make-quint-model-qualification-suite "zero-trust-pep-pdp" ZeroTrustPepPdpModel))
