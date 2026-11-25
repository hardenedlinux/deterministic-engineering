;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :clan/poo/object .def .o .get .ref .slot? .cc)
        (only-in :tao3k/yuanxu/configuration/json config-defaults)
        (only-in :clan/poo/type validate)
        "types.ss" "objects.ss" "config.ss"
        (only-in "../quint-methods/interface.ss" QuintMethods))
(export ThreatModelProfilesModule)

(def Methods (.get QuintMethods core exports))

(.def ThreatModelProfilesModule
  identity: 'threat-model-profiles
  tags: '(engineering profile quint)
  core:
  (.o
    admissions: (.o Config: (.o export-path: '(config) contract-path: '(config-type)))
    scope-contract: ScopeType
    exports:
    (.o
      config: Config
      config-type: QuintConfigType
      configure: (lambda (overrides) (validate QuintConfigType (config-defaults config overrides)))
      methods: Methods
      profiles: ThreatModelProfiles
      plan-for:
      (lambda (profile-name)
        (unless (.slot? ThreatModelProfiles profile-name)
          (error "unknown threat-model profile" profile-name))
        (def profile (.ref ThreatModelProfiles profile-name))
        (def policy (.cc (.get Methods config)
                         'timeout (.get config programs deterministic-engineering languages quint settings timeout)))
        ((.get Methods plan) (.get profile model) profile policy))))
  features: (.o))
