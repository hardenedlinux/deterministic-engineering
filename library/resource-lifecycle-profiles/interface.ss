;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :clan/poo/object .def .o)
        "types.ss" "objects.ss" "config.ss")
(export ProfileModule)
(.def ProfileModule
  identity: 'resource-lifecycle-profiles
  tags: '(engineering profile de.layer.profile)
  core:
  (.o
    admissions: (.o Config: (.o export-path: '(config) contract-path: '(config-type)))
    scope-contract: ScopeType
    exports:
    (.o
      config: Config
      config-type: ConfigType
      profiles: (.o LifecycleProfile LargerPayloadProfile)))
  features: (.o))
