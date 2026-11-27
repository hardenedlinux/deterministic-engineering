;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/storage/atomic-persistence-fsync-envelope/objects
                 AtomicPersistenceFsyncEnvelopeModel)
        "../../../support/quint-model-qualification.ss")
(export atomic-persistence-fsync-envelope-qualification-test)

(def atomic-persistence-fsync-envelope-qualification-test
  (make-quint-model-qualification-suite "atomic-persistence-fsync-envelope" AtomicPersistenceFsyncEnvelopeModel))
