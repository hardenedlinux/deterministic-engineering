;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/federated-org-reciprocity/objects
                 FederatedOrgReciprocityModel)
        "../../../support/quint-model-qualification.ss")
(export federated-org-reciprocity-qualification-test)

(def federated-org-reciprocity-qualification-test
  (make-quint-model-qualification-suite
    "federated-org-reciprocity"
    FederatedOrgReciprocityModel))
