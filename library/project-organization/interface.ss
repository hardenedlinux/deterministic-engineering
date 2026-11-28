;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
(import
  (only-in :clan/poo/object .def .o .get)
  "types.ss"
  "config.ss")
(export ProjectOrganizationLibrary)
(.def ProjectOrganizationLibrary
  identity: 'project-organization
  tags: '(engineering domain organization de.layer.foundation)
  core: (.o
          admissions: (.o
                        Config: (.o
                                  export-path: '(config)
                                  contract-path: '(contracts config)))
          scope-contract: (.get OrganizationScopeContract value-contract)
          exports: (.o (:: scope)
                     self: scope
                     config: Config
                     declaration: (.get scope config declaration)
                     entry: (.get scope config entry)
                     contracts: (.o
                                  model: OrganizationModelContract
                                  declaration: OrganizationDeclarationContract
                                  config: OrganizationConfigContract)))
  features: (.o))
