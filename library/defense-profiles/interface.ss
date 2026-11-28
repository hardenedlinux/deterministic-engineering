;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :clan/poo/object .def .o)
        "types.ss"
        "objects.ss")
(export DefenseProfilesModule)

(.def DefenseProfilesModule
  identity: 'defense-profiles
  tags: '(engineering profile defense de.layer.profile)
  profile-catalog: DefenseProfileRegistry
  core:
  (.o
    admissions: (.o)
    scope-contract: DefenseProfilesScopeType
    exports:
    (.o slot-specs: DefenseSlotSpecs
        default-slots: DefenseDefaultSlots
        governance-floor: DefenseGovernanceFloor
        profiles: DefenseProfiles
        registry: DefenseProfileRegistry
        converge: converge-defense-graph
        apply-runtime: apply-defense-runtime-profile))
  features: (.o))
