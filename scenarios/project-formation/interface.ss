;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

(import
  (only-in :yuanxu/module-system/source/declaration .def))
(.def LibraryProjectFormation
  identity: 'library-project-formation
  core: (.o
          requires: (.o
                      Library: (.o
                                 module-id: 'project-organization
                                 contract: OrganizationScopeContract)
                      Engine: (.o
                                module-id: 'project-formation
                                contract: FormationScopeContract)
                      Resources: (.o
                                   module-id: 'rust-resources
                                   contract: RustResourcesScopeContract))
          scope-contract: FormationScenarioContract
          exports: (project-formation-scope Library Engine Resources))
  features: (.o))
