;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/subprocess-pipe-capture-envelope/objects
                 SubprocessPipeCaptureEnvelopeModel)
        "../../../support/quint-model-qualification.ss")
(export subprocess-pipe-capture-envelope-qualification-test)

(def subprocess-pipe-capture-envelope-qualification-test
  (make-quint-model-qualification-suite "subprocess-pipe-capture-envelope" SubprocessPipeCaptureEnvelopeModel))
