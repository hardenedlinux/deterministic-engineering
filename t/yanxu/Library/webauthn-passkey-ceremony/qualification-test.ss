;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/webauthn-passkey-ceremony/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export webauthn-passkey-ceremony-qualification-test)

(def webauthn-passkey-ceremony-qualification-test
  (make-quint-model-qualification-suite
    "webauthn-passkey-ceremony"
    WebAuthnPasskeyCeremonyModel
    (.get ThreatModelProfiles webauthn-passkey-ceremony)))
