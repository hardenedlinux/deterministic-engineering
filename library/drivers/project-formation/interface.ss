;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

(import
  (only-in :yuanxu/module-system/source/declaration .def))
(.def ProjectFormation
  identity: 'project-formation
  admissions: (.o
                Config: (.o
                          export-path: '(semantics)
                          contract-path: '(contracts config)))
  core: (.o
          requires: (.o
                      Library: (.o
                                 module-id: 'project-organization
                                 contract: OrganizationScopeContract))
          scope-contract: FormationScopeContract
          exports: (.o
                     self: module-scope
                     library: Library
                     semantics: Config
                     contracts: (.o
                                  config: FormationConfigContract
                                  scope: FormationScopeContract)
                     program: FormationProgram
                     method-bindings: (bind-formation-methods Library)
                     reason: (.get module-scope method-bindings reason operation)
                     render: (.get module-scope method-bindings render operation)))
  features: (.o))
