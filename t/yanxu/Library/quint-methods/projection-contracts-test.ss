;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Loader-owned qualification tests for library/quint-methods:
;;; prototype dispatch, sealed Record contracts, structural AST static field & guard checks,
;;; native gerbil-parser CST/SpanEdit/overlay composition, and languages.quint Config admission.
(import :std/test
        :clan/poo/object
        (only-in :clan/poo/type validate TypeError?)
        (only-in :clan/poo/mop/clos/objects clos-failure?)
        (only-in :tao3k/yuanxu/configuration/json config-defaults)
        (only-in :deterministic-engineering/config Config)
        (only-in :deterministic-engineering/packages/quint-models/threat/execution/capabilities/objects
                 CapabilitiesModel)
        (only-in :deterministic-engineering/packages/quint-models/threat/execution/state-rollback/objects
                 StateRollbackModel)
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/zero-trust-pep-pdp/objects
                 ZeroTrustPepPdpModel
                 StalePolicyDecisionCountermodel)
        (only-in :deterministic-engineering/packages/quint-models/threat/identity/oauth-token-lifecycle/objects
                 OAuthTokenLifecycleModel)
        (only-in :deterministic-engineering/packages/quint-models/engineering/gc/tricolor-write-barrier/objects
                 TricolorWriteBarrierModel)
        (only-in :deterministic-engineering/packages/quint-models/engineering/parallel/hazard-pointers-tso/objects
                 HazardPointersTsoModel)
        :deterministic-engineering/library/quint-methods/types
        :deterministic-engineering/library/quint-methods/objects
        :deterministic-engineering/library/quint-methods/methods
        :deterministic-engineering/library/quint-methods/grammar
        (only-in :deterministic-engineering/library/quint-profiles/types QuintConfigType)
        (only-in :deterministic-engineering/library/quint-profiles/objects
                 quint-model->verification-profile))
(export quint-methods-projection-contracts-test)

(def quint-methods-projection-contracts-test
  (test-suite "quint-methods projection, sealed contracts, AST checks, and gerbil-parser composer"
    (test-case "unknown prototype fails dispatch on quint-module and quint-plan"
      (def alien (.o identity: 'alien quint-module: "alien"))
      (def rollback-prof (quint-model->verification-profile StateRollbackModel))
      (check-exception (quint-module alien) clos-failure?)
      (check-exception
        (quint-plan alien rollback-prof DefaultQuintPolicy)
        clos-failure?))

    (test-case "sealed contracts reject invalid steps, cross-domain misuse, bad AST fields, and missing guards"
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
        TypeError?)
      (def strict-cap
        (.cc (quint-model->verification-profile CapabilitiesModel)
             'require-countermodels? #t))
      (check-exception (quint-plan CapabilitiesModel strict-cap DefaultQuintPolicy) error?)
      (check-exception (validate ThreatDomainModelType TricolorWriteBarrierModel) TypeError?)
      (check-exception (validate EngineeringDomainModelType ZeroTrustPepPdpModel) TypeError?)
      (check-exception
        (validate EngineeringDomainModelType
          (.cc TricolorWriteBarrierModel 'countermodels '()))
        TypeError?)
      (check-exception
        (validate QuintDomainModelType
          (.cc ZeroTrustPepPdpModel 'guards '((unrelated-guard "true"))))
        TypeError?)
      (check-exception
        (validate QuintDomainModelType
          (.cc HazardPointersTsoModel 'safety '(not (= (. h nonexistentField) 5))))
        TypeError?)
      (check-exception
        (validate QuintDomainModelType
          (.cc HazardPointersTsoModel 'transitions
               '((step (action step () (set-h (typoField #t)))))))
        TypeError?)
      (check-exception
        (validate QuintDomainModelType
          (.cc ZeroTrustPepPdpModel 'countermodels
               (list (.cc StalePolicyDecisionCountermodel
                          'derive-from-transition 'policyAllow))))
        TypeError?))

    (test-case "native gerbil-parser CST, SpanEdit, and structural overlay compose enforce parity & fail-closed"
      (def hp-src (quint-module HazardPointersTsoModel))
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
      ;; Pure-Scheme .qnt-to-.qnt overlay compose with module rename, dedup, override,
      ;; mid-decl placement, and run tail:
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
      (def oauth-src (quint-module OAuthTokenLifecycleModel))
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

    (test-case "languages.quint Config validates defaults and refuses invalid settings"
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
        TypeError?))

    (test-case "F3 quint-guard-audit classifies witnessed guards, rejects unwitnessed/redundant guards, and admits explicit preconditions"
      (def pass-report (quint-guard-audit ZeroTrustPepPdpModel))
      (validate QuintGuardAuditReportType pass-report)
      (check-equal? (.get pass-report passed?) #t)
      (check-equal? (.get pass-report unwitnessed-guards) '())
      (check-equal? (.get pass-report undeclared-ast-guards) '())
      ;; Removing one countermodel must fail the F3 guard necessity audit:
      (def unwitnessed-model
        (.cc ZeroTrustPepPdpModel 'countermodels (list StalePolicyDecisionCountermodel)))
      (def fail-report (quint-guard-audit unwitnessed-model))
      (check-equal? (.get fail-report passed?) #f)
      (check-equal? (.get fail-report unwitnessed-guards) '(policy-active))
      ;; Explicit 'precondition annotation justifies a domain framing guard:
      (def precond-model
        (.cc unwitnessed-model
             'guard-classifications '((policy-active precondition "Explicit domain well-formedness frame"))))
      (def precond-report (quint-guard-audit precond-model))
      (check-equal? (.get precond-report passed?) #t)
      ;; Explicit 'redundant annotation still fails passed? so redundant defenses cannot pass silently:
      (def redundant-model
        (.cc unwitnessed-model
             'guard-classifications '((policy-active redundant "Pruned guard left safety intact"))))
      (def redundant-report (quint-guard-audit redundant-model))
      (check-equal? (.get redundant-report passed?) #f))))
