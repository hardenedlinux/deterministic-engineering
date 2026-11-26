;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/oidc-federation/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export oidc-federation-qualification-test)

(def oidc-federation-qualification-test
  (make-quint-model-qualification-suite
    "oidc-federation"
    OidcFederationModel
    (.get ThreatModelProfiles oidc-federation)))
