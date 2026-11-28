;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :clan/poo/object .def .o)
        "types.ss" "objects.ss" "config.ss" "methods.ss")
(export SourceContracts)
(.def SourceContracts
  identity: 'source-contracts
  tags: '(engineering method verification source-contract de.layer.method)
  core:
  (.o
    admissions:
    (.o Config: (.o export-path: '(config) contract-path: '(config-type)))
    scope-contract: SourceContractScopeType
    exports:
    (.o
      config: Config
      config-type: SourceContractConfig
      configure: (lambda (overrides) (resolve-config config overrides))
      strategies:
      (.o cbmc: CbmcExecutor.
          native: NativeExecutor.
          c11: C11Language.
          cpp11: Cpp11Language.
          direct: DirectContract.
          enforce: CheckedContract.
          replace: ReplacedContract.)
      scenario: SourceContractScenario.
      plan: (lambda (executor profile) (contract-plan config executor profile))
      contracts:
      (.o scope: SourceContractScopeType
          scenario: SourceContractScenario
          profile: SourceContractProfile
          tools: SourceContractTools
          plan: SourceContractPlan)))
  features: (.o))
