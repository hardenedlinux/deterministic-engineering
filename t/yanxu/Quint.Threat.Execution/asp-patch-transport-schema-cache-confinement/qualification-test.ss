;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/execution/asp-patch-transport-schema-cache-confinement/objects
                 AspPatchTransportSchemaCacheConfinementModel)
        "../../../support/quint-model-qualification.ss")
(export asp-patch-transport-schema-cache-confinement-qualification-test)

(def asp-patch-transport-schema-cache-confinement-qualification-test
  (make-quint-model-qualification-suite
    "asp-patch-transport-schema-cache-confinement"
    AspPatchTransportSchemaCacheConfinementModel))
