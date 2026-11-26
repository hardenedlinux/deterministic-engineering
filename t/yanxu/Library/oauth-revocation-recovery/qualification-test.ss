;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/oauth-revocation-recovery/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export oauth-revocation-recovery-qualification-test)

(def oauth-revocation-recovery-qualification-test
  (make-quint-model-qualification-suite
    "oauth-revocation-recovery"
    OAuthRevocationRecoveryModel
    (.get ThreatModelProfiles oauth-revocation-recovery)))
