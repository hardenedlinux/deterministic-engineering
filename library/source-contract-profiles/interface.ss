;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :clan/poo/object .def .o .get)
        (only-in :tao3k/yuanxu/configuration/json config-defaults)
        (only-in :clan/poo/type validate)
        "types.ss" "objects.ss" "config.ss"
        (only-in "../source-contracts/interface.ss" SourceContracts))
(export ProfileModule)
(def Driver (.get SourceContracts core exports))
(.def ProfileModule
  identity: 'source-contract-profiles
  tags: '(engineering profile source-contract)
  core:
  (.o
    admissions: (.o Config: (.o export-path: '(config) contract-path: '(config-type)))
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
