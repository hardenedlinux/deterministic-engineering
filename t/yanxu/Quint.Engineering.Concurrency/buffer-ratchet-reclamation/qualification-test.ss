;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/buffer-ratchet-reclamation/objects
                 BufferRatchetReclamationModel)
        "../../../support/quint-model-qualification.ss")
(export buffer-ratchet-reclamation-qualification-test)

(def buffer-ratchet-reclamation-qualification-test
  (make-quint-model-qualification-suite "buffer-ratchet-reclamation" BufferRatchetReclamationModel))
