;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/gc-safepoint-handshake/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export gc-safepoint-handshake-qualification-test)

(def gc-safepoint-handshake-qualification-test
  (make-quint-model-qualification-suite
    "gc-safepoint-handshake"
    SafepointHandshakeModel
    (.get ThreatModelProfiles gc-safepoint-handshake)))
