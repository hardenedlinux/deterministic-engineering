;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :yuanxu/module-system/source/declaration .def)
        (only-in :yuanxu/configuration/json config-defaults)
        (only-in :clan/poo/mop validate))
(.def ProfileModule
  identity: 'source-contract-profiles
  tags: '(engineering profile source-contract)
  admissions: (.o Config: (.o export-path: '(config) contract-path: '(config-type)))
  core:
  (.o
    requires: (.o Driver: (.o module-id: 'source-contracts))
    scope-contract: ScopeType
    exports:
    (.o
      config: Config
      config-type: ConfigType
      configure: (lambda (overrides) (validate ConfigType (config-defaults config overrides)))
      plan-library: Driver
      profiles: (source-contract-profiles (.get Driver strategies))
      languages:
      (.o
        c:
        (configured-language Driver profiles (.get Driver strategies c11)
          (.get config programs deterministic-engineering languages c))
        cpp:
        (configured-language Driver profiles (.get Driver strategies cpp11)
          (.get config programs deterministic-engineering languages cpp)))))
  features: (.o))
