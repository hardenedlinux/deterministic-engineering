;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :clan/poo/object .def .o)
        "types.ss"
        "objects.ss")
(export DefensiveBoundaries)

(.def DefensiveBoundaries
  identity: 'defensive-boundaries
  tags: '(engineering
          domain
          defense
          de.layer.defense
          defense.pathology.masking
          defense.pathology.misplaced
          defense.pathology.over-blocking
          defense.pathology.bloat
          defense.property.mbt-paired)
  core:
  (.o
    admissions: (.o)
    scope-contract: DefensiveBoundariesScopeType
    exports:
    (.o catalog: DefensiveAntiPatternCatalog
        contrast-subjects: DefensiveContrastSubjects
        lookup-by-pathology: anti-patterns-by-pathology
        contracts: (.o pathology: DefensivePathologyType
                       mutability: PremiseMutabilityType
                       enforcement: CheckEnforcementKindType
                       entry: AntiPatternEntryType
                       contrast: ContrastSubjectType
                       scope: DefensiveBoundariesScopeType)))
  features: (.o))
