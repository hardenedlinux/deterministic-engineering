;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/identity/oidc-federation/objects
                 OidcFederationModel)
        "../../../support/quint-model-qualification.ss")
(export oidc-federation-qualification-test)

(def oidc-federation-qualification-test
  (make-quint-model-qualification-suite "oidc-federation" OidcFederationModel))
