;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/identity/webauthn-passkey-ceremony/objects
                 WebAuthnPasskeyCeremonyModel)
        "../../../support/quint-model-qualification.ss")
(export webauthn-passkey-ceremony-qualification-test)

(def webauthn-passkey-ceremony-qualification-test
  (make-quint-model-qualification-suite "webauthn-passkey-ceremony" WebAuthnPasskeyCeremonyModel))
