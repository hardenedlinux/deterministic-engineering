;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/zero-trust-pep-pdp/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export zero-trust-pep-pdp-qualification-test)

(def zero-trust-pep-pdp-qualification-test
  (make-quint-model-qualification-suite
    "zero-trust-pep-pdp"
    ZeroTrustPepPdpModel
    (.get ThreatModelProfiles zero-trust-pep-pdp)))
