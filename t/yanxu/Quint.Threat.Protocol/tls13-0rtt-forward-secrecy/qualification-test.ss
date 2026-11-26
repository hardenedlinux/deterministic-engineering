;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/protocol/tls13-0rtt-forward-secrecy/objects
                 Tls13ZeroRttForwardSecrecyModel)
        "../../../support/quint-model-qualification.ss")
(export tls13-0rtt-forward-secrecy-qualification-test)

(def tls13-0rtt-forward-secrecy-qualification-test
  (make-quint-model-qualification-suite "tls13-0rtt-forward-secrecy" Tls13ZeroRttForwardSecrecyModel))
