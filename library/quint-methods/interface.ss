;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :clan/poo/object .def .o)
        "types.ss"
        "objects.ss"
        "config.ss"
        "methods.ss"
        "grammar.ss")
(export QuintMethods)

(.def QuintMethods
  identity: 'quint-methods
  tags: '(engineering method quint de.layer.method defense.property.guard-pruned quint.native-ssot)
  core:
  (.o
    admissions: (.o Config: (.o export-path: '(config) contract-path: '(config-type)))
    scope-contract: QuintMethodsScopeType
    exports:
    (.o config: Config
        config-type: QuintPolicyType
        parse-spec: parse-quint-model-spec
        project-readme: quint-model-readme
        plan: quint-plan
        audit-guards: quint-guard-audit
        contracts: (.o policy: QuintPolicyType
                       plan: QuintPlanType
                       profile: QuintProfileType
                       step: QuintCheckStep
                       guard-audit: QuintGuardAuditReportType
                       scope: QuintMethodsScopeType)))
  features: (.o))
