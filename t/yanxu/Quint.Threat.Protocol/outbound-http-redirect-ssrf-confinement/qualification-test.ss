;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/protocol/outbound-http-redirect-ssrf-confinement/objects
                 OutboundHttpRedirectSsrfConfinementModel)
        "../../../support/quint-model-qualification.ss")
(export outbound-http-redirect-ssrf-confinement-qualification-test)

(def outbound-http-redirect-ssrf-confinement-qualification-test
  (make-quint-model-qualification-suite
    "outbound-http-redirect-ssrf-confinement"
    OutboundHttpRedirectSsrfConfinementModel))
