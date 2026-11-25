;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :clan/poo/object .def .o)
        "types.ss" "objects.ss" "config.ss" "methods.ss")
(export QuintMethods)
(.def QuintMethods
  identity: 'quint-methods
  tags: '(engineering method quint)
  core:
  (.o
    admissions: (.o Config: (.o export-path: '(config) contract-path: '(config-type)))
    scope-contract: QuintMethodsScopeType
    exports:
    (.o
      config: Config
      config-type: QuintPolicyType
      project-module: quint-module
      plan: quint-plan
      contracts: (.o policy: QuintPolicyType
                     plan: QuintPlanType
                     profile: QuintProfileType
                     step: QuintCheckStep
                     scope: QuintMethodsScopeType)))
  features: (.o))
