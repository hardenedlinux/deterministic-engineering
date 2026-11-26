;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/device-authorization/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export device-authorization-qualification-test)

(def device-authorization-qualification-test
  (make-quint-model-qualification-suite
    "device-authorization"
    DeviceAuthorizationModel
    (.get ThreatModelProfiles device-authorization)))
