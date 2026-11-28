;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/storage/mvcc-ssi-write-skew/objects
                 MvccSsiWriteSkewModel)
        "../../../support/quint-model-qualification.ss")
(export mvcc-ssi-write-skew-qualification-test)

(def mvcc-ssi-write-skew-qualification-test
  (make-quint-model-qualification-suite "mvcc-ssi-write-skew" MvccSsiWriteSkewModel))
