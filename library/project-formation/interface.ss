;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import
  (only-in :clan/poo/object .def .o .get)
  "types.ss" "config.ss" "func.ss"
  (only-in "../project-organization/interface.ss" ProjectOrganizationLibrary))
(export ProjectFormation)
(def Library (.get ProjectOrganizationLibrary core exports))
(.def ProjectFormation
  identity: 'project-formation
  tags: '(engineering driver organization)
  core: (.o
          admissions: (.o
                        Config: (.o
                                  export-path: '(config)
                                  contract-path: '(contracts config)))
          scope-contract: (.get FormationScopeContract value-contract)
          exports: (.o (:: module-scope)
                     self: module-scope
                     library: Library
                     config: Config
                     semantics: Config
                     contracts: (.o
                                  config: FormationConfigContract
                                  scope: FormationScopeContract)
                     program: FormationProgram
                     method-bindings: (bind-formation-methods Library)
                     reason: (.get module-scope method-bindings reason operation)
                     render: (.get module-scope method-bindings render operation)))
  features: (.o))
