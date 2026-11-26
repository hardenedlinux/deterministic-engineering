;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/protocol/mls-ratchet-pcs/objects
                 MlsRatchetPcsModel)
        "../../../support/quint-model-qualification.ss")
(export mls-ratchet-pcs-qualification-test)

(def mls-ratchet-pcs-qualification-test
  (make-quint-model-qualification-suite "mls-ratchet-pcs" MlsRatchetPcsModel))
