;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
(import
  :clan/poo/object
  "objects.ss")
(export
  Config)
(def Config
  (.o
    entry: ProjectOrganization
    declaration: OrganizationDeclaration))
