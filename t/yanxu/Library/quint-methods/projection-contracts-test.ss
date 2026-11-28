;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Loader-owned qualification tests for library/quint-methods (10.204):
;;; hard sealed .qnt-SSOT Record contracts (mechanically blocking state/guards/transitions
;;; duplication in Scheme), native gerbil-parser LR spec/CST/SpanEdit/overlay composition,
;;; F3 guard audit, and languages.quint Config admission.
(import :std/test
        :clan/poo/object
        (only-in :clan/poo/type validate TypeError?)
        (only-in :clan/poo/mop/clos/objects clos-failure?)
        (only-in :tao3k/yuanxu/testing yuanxu-test-case)
        (only-in :tao3k/yuanxu/configuration/json config-defaults)
        (only-in :deterministic-engineering/config Config)
        (only-in :deterministic-engineering/packages/quint-models/threat/execution/capabilities/objects
                 CapabilitiesModel)
        (only-in :deterministic-engineering/packages/quint-models/threat/execution/state-rollback/objects
                 StateRollbackModel)
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/zero-trust-pep-pdp/objects
                 ZeroTrustPepPdpModel)
        (only-in :deterministic-engineering/packages/quint-models/threat/identity/oauth-token-lifecycle/objects
                 OAuthTokenLifecycleModel)
        (only-in :deterministic-engineering/packages/quint-models/engineering/gc/tricolor-write-barrier/objects
                 TricolorWriteBarrierModel)
        (only-in :deterministic-engineering/packages/quint-models/engineering/parallel/hazard-pointers-tso/objects
                 HazardPointersTsoModel)
        (only-in :deterministic-engineering/packages/quint-models/engineering/defense/model-weight-inference-attestation/objects
                 ModelWeightInferenceAttestationModel)
        :deterministic-engineering/library/quint-methods/types
        :deterministic-engineering/library/quint-methods/objects
        :deterministic-engineering/library/quint-methods/methods
        :deterministic-engineering/library/quint-methods/grammar
        (only-in :deterministic-engineering/library/quint-profiles/types QuintConfigType)
        (only-in :deterministic-engineering/library/quint-profiles/objects
                 quint-model->verification-profile)
        (only-in "../../../support/quint-model-qualification.ss" read-quint-model-source))
(export quint-methods-projection-contracts-test)

(def quint-methods-projection-contracts-test
  (test-suite "quint-methods hard .qnt-SSOT sealed contracts, native LR parser, and SpanEdit composer"
    (yuanxu-test-case "unknown prototype fails dispatch on quint-plan and quint-guard-audit"
      (def alien (.o identity: 'alien quint-module: "alien"))
      (def rollback-prof (quint-model->verification-profile StateRollbackModel))
      (def rollback-src (read-quint-model-source StateRollbackModel))
      (check-exception (quint-guard-audit alien rollback-src) clos-failure?)
      (check-exception
        (quint-plan alien rollback-src rollback-prof DefaultQuintPolicy)
        clos-failure?))

    (yuanxu-test-case "hard sealed QuintDomainModelType mechanically rejects ALL duplicated Quint AST slots in Scheme"
      (validate QuintDomainModelType ModelWeightInferenceAttestationModel)
      (validate EngineeringDomainModelType ModelWeightInferenceAttestationModel)
      (validate ThreatDomainModelType ZeroTrustPepPdpModel)
      (check-exception (validate ThreatDomainModelType TricolorWriteBarrierModel) TypeError?)
      (check-exception (validate EngineeringDomainModelType ZeroTrustPepPdpModel) TypeError?)
      ;; Every legacy Quint AST slot MUST throw TypeError on sealed QuintDomainModelShape:
      (check-exception
        (validate QuintDomainModelType
          (.cc ModelWeightInferenceAttestationModel 'state '((x "int" "0"))))
        TypeError?)
      (check-exception
        (validate QuintDomainModelType
          (.cc ModelWeightInferenceAttestationModel 'guards '((g "true"))))
        TypeError?)
      (check-exception
        (validate QuintDomainModelType
          (.cc ModelWeightInferenceAttestationModel 'transitions '((step "action step = h' = h"))))
        TypeError?)
      (check-exception
        (validate QuintDomainModelType
          (.cc ModelWeightInferenceAttestationModel 'safety "true"))
        TypeError?)
      (check-exception
        (validate QuintDomainModelType
          (.cc ModelWeightInferenceAttestationModel 'traces '()))
        TypeError?)
      (check-exception
        (validate QuintDomainModelType
          (.cc ModelWeightInferenceAttestationModel 'countermodels '()))
        TypeError?)
      (check-exception
        (validate QuintDomainModelType
          (.cc ModelWeightInferenceAttestationModel 'parameters '()))
        TypeError?)
      (check-exception
        (validate QuintDomainModelType
          (.cc ModelWeightInferenceAttestationModel 'verify-depth 10))
        TypeError?)
      ;; Sealed QuintCheckStep still rejects invalid countermodel expectations:
      (check-exception
        (validate QuintCheckStep
          (.o label: "bad-counter"
              command: '("verify" "X.qnt")
              expected-exit: 0
              kind: "required-countermodel"))
        TypeError?)
      (check-exception
        (validate QuintCheckStep
          (.o label: "bad-counter-no-guard"
              command: '("verify" "X.qnt")
              expected-exit: 1
              kind: "required-countermodel"))
        TypeError?))

    (yuanxu-test-case "native .qnt parser derives plan, F3 guard audit, and fails closed on parity/countermodel violations"
      (def cap-src (read-quint-model-source CapabilitiesModel))
      (def strict-cap
        (.cc (quint-model->verification-profile CapabilitiesModel)
             'require-countermodels? #t))
      (check-exception (quint-plan CapabilitiesModel cap-src strict-cap DefaultQuintPolicy) error?)
      (def b21-src (read-quint-model-source ModelWeightInferenceAttestationModel))
      (def spec (parse-quint-model-spec b21-src))
      (check-equal? (.get spec module-name) "model_weight_inference_attestation")
      (check-equal? (.get spec has-state-record?) #t)
      (check-equal? (.get spec has-step?) #t)
      (check-equal? (length (.get spec countermodels)) 3)
      (def b21-prof (quint-model->verification-profile ModelWeightInferenceAttestationModel))
      (def b21-plan (quint-plan ModelWeightInferenceAttestationModel b21-src b21-prof DefaultQuintPolicy))
      (validate QuintPlanType b21-plan)
      (check-equal? (length (.get b21-plan steps)) 6)
      (def b21-audit (quint-guard-audit ModelWeightInferenceAttestationModel b21-src))
      (validate QuintGuardAuditReportType b21-audit)
      (check-equal? (.get b21-audit passed?) #t)
      (check-equal? (length (.get b21-audit witnessed-guards)) 3)
      ;; Fail-closed parity checks: mismatched module name or missing @countermodel step in CST must error:
      (check-exception
        (quint-plan
          (.cc ModelWeightInferenceAttestationModel 'quint-module "wrong_module_name")
          b21-src b21-prof DefaultQuintPolicy)
        error?)
      (check-exception
        (parse-quint-model-spec
          "// @countermodel bogus-guard step=nonExistentStep max-steps=6 itf=\"true\"\nmodule demo { val safety = true }\n")
        error?)
      ;; Engineering stateful .qnt with zero @countermodel directives MUST fail F3 guard audit:
      (def no-cm-report
        (quint-guard-audit
          (.cc ModelWeightInferenceAttestationModel
               'quint-module "bare_eng"
               'identity 'engineering.defense.bare-eng)
          "// @quint-model engineering.defense.bare-eng\nmodule bare_eng {\n  type State = { x: int }\n  var h: State\n  action init = h' = { x: 0 }\n  action step = h' = h\n  val safety = h.x == 0\n}\n"))
      (check-equal? (.get no-cm-report passed?) #f))

    (yuanxu-test-case "native gerbil-parser CST, SpanEdit, and structural overlay compose enforce parity & fail-closed"
      (def hp-src (read-quint-model-source HazardPointersTsoModel))
      (def hp-decls (quint-cst-declarations hp-src))
      (check-equal? (>= (length hp-decls) 15) #t)
      (def edited (quint-span-append-decl hp-src "val extraSafety = safety"))
      (check-equal? (.get edited verified?) #t)
      (check-equal? (quint-source-qualified? (.get edited source)) #t)
      (def strengthened (quint-span-strengthen-safety hp-src "h.readerPc <= 5"))
      (check-equal? (.get strengthened verified?) #t)
      (check-equal? (quint-source-qualified? (.get strengthened source)) #t)
      (def extended (quint-span-extend-step (.get strengthened source) "readerLoadPtr"))
      (check-equal? (.get extended verified?) #t)
      (check-equal? (quint-source-qualified? (.get extended source)) #t)
      (def overlay-src
        (string-append
          "module hp_overlay {\n"
          "  type State = { readerPc: int, auditSeq: int }\n"
          "  action init = h' = { readerPc: 0, auditSeq: 0 }\n"
          "  action bumpAudit = h' = h.with(\"auditSeq\", h.auditSeq + 1)\n"
          "  action step = any { bumpAudit }\n"
          "  val safety = h.auditSeq >= 0\n"
          "  run overlayAuditTest = init.then(bumpAudit).then(all { assert(h.auditSeq == 1), assert(safety), h' = h })\n"
          "}\n"))
      (def composed (quint-span-compose-overlay hp-src overlay-src))
      (check-equal? (.get composed verified?) #t)
      (check-equal? (quint-source-qualified? (.get composed source)) #t)
      (check-equal? (and (string-contains (.get composed source) "module hp_overlay") #t) #t)
      (check-equal? (and (string-contains (.get composed source) "auditSeq: int") #t) #t)
      (check-equal? (and (string-contains (.get composed source) "bumpAudit") #t) #t)
      (check-equal? (and (string-contains (.get composed source) "h.auditSeq >= 0") #t) #t)
      ;; Refusal parity controls: syntax error, type conflict, missing init, uninit field, symbol collision.
      (check-exception (quint-span-append-decl hp-src "val brokenSyntax = === ???") error?)
      (check-exception (quint-span-strengthen-safety hp-src "=== broken ===") error?)
      (def oauth-src (read-quint-model-source OAuthTokenLifecycleModel))
      (check-exception
        (quint-span-compose-overlay oauth-src
          "module bad_t {\n  type State = { authEpoch: bool }\n  action init = h' = { authEpoch: false }\n}\n")
        error?)
      (check-exception
        (quint-span-compose-overlay oauth-src
          "module bad_i {\n  type State = { extraFlag: bool }\n}\n")
        error?)
      (check-exception
        (quint-span-compose-overlay oauth-src
          "module bad_u {\n  type State = { extraA: bool, extraB: int }\n  action init = h' = { extraA: false }\n}\n")
        error?)
      (check-exception
        (quint-span-compose-overlay oauth-src
          "module bad_c {\n  action beginOAuth = h' = h\n}\n")
        error?))

    (yuanxu-test-case "languages.quint Config validates defaults and refuses invalid settings"
      (validate QuintConfigType Config)
      (def enabled
        (config-defaults Config
          (.o programs:
              (.o deterministic-engineering:
                  (.o languages:
                      (.o quint:
                          (.o enable: #t
                              settings: (.o timeout: 60))))))))
      (validate QuintConfigType enabled)
      (check-equal? (.get enabled programs deterministic-engineering languages quint enable) #t)
      (check-equal? (.get enabled programs deterministic-engineering languages quint settings timeout) 60)
      (check-equal? (.get enabled programs deterministic-engineering languages quint settings profile)
                    'assurance.bounded-proof)
      (check-exception
        (validate QuintConfigType
          (config-defaults Config
            (.o programs:
                (.o deterministic-engineering:
                    (.o languages:
                        (.o quint: (.o settings: (.o timout: 60))))))))
        TypeError?)
      (check-exception
        (validate QuintConfigType
          (config-defaults Config
            (.o programs:
                (.o deterministic-engineering:
                    (.o languages:
                        (.o quint: (.o settings: (.o timeout: 999))))))))
        TypeError?))))
