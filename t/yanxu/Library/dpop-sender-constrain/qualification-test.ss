;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/dpop-sender-constrain/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export dpop-sender-constrain-qualification-test)

(def dpop-sender-constrain-qualification-test
  (make-quint-model-qualification-suite
    "dpop-sender-constrain"
    DpopSenderConstrainModel
    (.get ThreatModelProfiles dpop-sender-constrain)))
