;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :yuanxu/module-system/source/declaration .def))
(.def SourceContracts
  identity: 'source-contracts
  tags: '(engineering method verification source-contract)
  admissions:
  (.o Config: (.o export-path: '(config) contract-path: '(config-type)))
  core:
  (.o
    requires: (.o)
    scope-contract: SourceContractScopeType
    exports:
    (.o
      config: Config
      config-type: SourceContractConfig
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
      (.o scenario: SourceContractScenario
          profile: SourceContractProfile
          tools: SourceContractTools
          plan: SourceContractPlan)))
  features: (.o))
