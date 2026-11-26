;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :clan/poo/object .def .o)
        (only-in :clan/poo/type validate)
        (only-in :tao3k/yuanxu/configuration/json config-defaults)
        "types.ss"
        "objects.ss"
        "config.ss")
(export QuintProfiles)

(.def QuintProfiles
  identity: 'quint-profiles
  tags: '(engineering profile quint)
  profile-catalog: QuintProfileRegistry
  core:
  (.o
    admissions: (.o Config: (.o export-path: '(config) contract-path: '(config-type)))
    scope-contract: QuintProfilesScopeType
    exports:
    (.o config: Config
        config-type: QuintConfigType
        configure: (lambda (overrides)
                     (validate QuintConfigType (config-defaults config overrides)))
        slot-specs: QuintModelSlotSpecs
        default-slots: QuintModelDefaultSlots
        stateless-default-slots: QuintStatelessModelDefaultSlots
        governance-floor: QuintModelGovernanceFloor
        assurance: QuintAssuranceProfiles
        bound: QuintBoundProfiles
        governance: QuintGovernanceProfiles
        registry: QuintProfileRegistry
        converge: converge-quint-graph
        model->profile: quint-model->verification-profile))
  features: (.o))
