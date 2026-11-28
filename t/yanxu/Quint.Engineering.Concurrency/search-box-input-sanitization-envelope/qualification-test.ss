;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/search-box-input-sanitization-envelope/objects
                 SearchBoxInputSanitizationEnvelopeModel)
        "../../../support/quint-model-qualification.ss")
(export search-box-input-sanitization-envelope-qualification-test)

(def search-box-input-sanitization-envelope-qualification-test
  (make-quint-model-qualification-suite "search-box-input-sanitization-envelope" SearchBoxInputSanitizationEnvelopeModel))
