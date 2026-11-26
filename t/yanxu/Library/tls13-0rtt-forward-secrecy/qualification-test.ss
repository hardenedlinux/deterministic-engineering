;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/tls13-0rtt-forward-secrecy/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export tls13-0rtt-forward-secrecy-qualification-test)

(def tls13-0rtt-forward-secrecy-qualification-test
  (make-quint-model-qualification-suite
    "tls13-0rtt-forward-secrecy"
    Tls13ZeroRttForwardSecrecyModel
    (.get ThreatModelProfiles tls13-0rtt-forward-secrecy)))
