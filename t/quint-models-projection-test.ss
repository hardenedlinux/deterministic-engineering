;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; L4 Scheme tests: declarative Quint types, prototype dispatch, plan contracts,
;;; languages.quint Config admission, and same-commit reprojection match.
(import
  :std/test
  :std/source
  :std/misc/ports
  :clan/poo/object
  (only-in :clan/poo/type validate TypeError?)
  (only-in :clan/poo/mop/clos/objects clos-failure?)
  (only-in :tao3k/yuanxu/configuration/json config-defaults)
  "../config.ss"
  "../library/threat-capabilities/objects.ss"
  "../library/authority-currentness/objects.ss"
  "../library/effect-handoff/objects.ss"
  "../library/effect-containment/objects.ss"
  "../library/state-rollback/objects.ss"
  "../library/zero-trust-pep-pdp/objects.ss"
  "../library/workload-identity-rotation/objects.ss"
  "../library/microsegmentation-egress/objects.ss"
  "../library/oauth-token-lifecycle/objects.ss"
  "../library/oidc-federation/objects.ss"
  "../library/device-authorization/objects.ss"
  "../library/gc-tricolor-barrier/objects.ss"
  "../library/gc-safepoint-handshake/objects.ss"
  "../library/parallel-epoch-reclamation/objects.ss"
  "../library/parallel-work-stealing/objects.ss"
  "../library/concurrency-structured-cancel/objects.ss"
  "../library/quint-methods/types.ss"
  "../library/quint-methods/objects.ss"
  "../library/quint-methods/methods.ss"
  "../library/threat-model-profiles/types.ss"
  "../library/threat-model-profiles/objects.ss")
(export quint-models-projection-test)

(def repo-root (path-normalize (path-expand ".." (path-directory (this-source-file)))))

(def quint-models-projection-test
  (test-suite "Quint models projection, sealed contracts and same-commit consistency"
    (test-case "unknown prototype fails dispatch on quint-module and quint-plan"
      (def alien (.o identity: 'alien quint-module: "alien"))
      (check-exception (quint-module alien) clos-failure?)
      (check-exception
        (quint-plan alien (.get ThreatModelProfiles exact-effect-host) DefaultQuintPolicy)
        clos-failure?))

    (test-case "sealed contracts reject incomplete countermodel steps and missing countermodels"
      ;; Required countermodel with exit 0 or missing dropped-guard must fail validation.
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
      ;; Profile requiring countermodels refuses a model with none.
      (def strict-cap
        (.cc (.get ThreatModelProfiles threat-capabilities) 'require-countermodels? #t))
      (check-exception (quint-plan CapabilitiesModel strict-cap DefaultQuintPolicy) error?)
      ;; Relational sealed Record checks: unknown dropped-guard and cross-domain misuse must refuse.
      (check-exception
        (validate ThreatDomainModelType TricolorWriteBarrierModel)
        TypeError?)
      (check-exception
        (validate EngineeringDomainModelType ZeroTrustPepPdpModel)
        TypeError?)
      (check-exception
        (validate EngineeringDomainModelType (.cc TricolorWriteBarrierModel 'countermodels '()))
        TypeError?)
      (check-exception
        (validate QuintDomainModelType
          (.cc ZeroTrustPepPdpModel 'guards '((unrelated-guard "true"))))
        TypeError?))

    (test-case "languages.quint Config validates defaults and refuses invalid settings"
      (validate QuintConfigType Config)
      (def enabled
        (config-defaults Config
          (.o programs: (.o deterministic-engineering:
              (.o languages: (.o quint: (.o enable: #t settings: (.o timeout: 60))))))))
      (validate QuintConfigType enabled)
      (check-equal? (.get enabled programs deterministic-engineering languages quint enable) #t)
      (check-equal? (.get enabled programs deterministic-engineering languages quint settings timeout) 60)
      (check-equal? (.get enabled programs deterministic-engineering languages quint settings profile)
                    'exact-effect-host)
      ;; Unknown field in settings must refuse.
      (check-exception
        (validate QuintConfigType
          (config-defaults Config
            (.o programs: (.o deterministic-engineering:
                (.o languages: (.o quint: (.o settings: (.o timout: 60))))))))
        TypeError?)
      ;; Out-of-range timeout must refuse.
      (check-exception
        (validate QuintConfigType
          (config-defaults Config
            (.o programs: (.o deterministic-engineering:
                (.o languages: (.o quint: (.o settings: (.o timeout: 999))))))))
        TypeError?))

    (test-case "same-commit reprojection matches packages/quint-models/threat/ byte-for-byte"
      (for-each
        (lambda (pair)
          (def model (car pair))
          (def profile (cdr pair))
          (def expected-text (quint-module model))
          (def disk-path
            (path-expand (.get model quint-file)
              (path-expand (.get model domain-dir)
                (path-expand "packages/quint-models" repo-root))))
          (check-equal? (file-exists? disk-path) #t)
          (check-equal? (read-file-string disk-path) expected-text)
          (def plan (quint-plan model profile DefaultQuintPolicy))
          (validate QuintPlanType plan))
        (list
          (cons CapabilitiesModel (.get ThreatModelProfiles threat-capabilities))
          (cons AuthorityCurrentnessModel (.get ThreatModelProfiles authority-currentness))
          (cons EffectHandoffModel (.get ThreatModelProfiles effect-handoff))
          (cons EffectContainmentModel (.get ThreatModelProfiles effect-containment))
          (cons StateRollbackModel (.get ThreatModelProfiles exact-effect-host))
          (cons ZeroTrustPepPdpModel (.get ThreatModelProfiles zero-trust-pep-pdp))
          (cons WorkloadIdentityRotationModel (.get ThreatModelProfiles workload-identity-rotation))
          (cons MicrosegmentationEgressModel (.get ThreatModelProfiles microsegmentation-egress))
          (cons OAuthTokenLifecycleModel (.get ThreatModelProfiles oauth-token-lifecycle))
          (cons OidcFederationModel (.get ThreatModelProfiles oidc-federation))
          (cons DeviceAuthorizationModel (.get ThreatModelProfiles device-authorization))
          (cons TricolorWriteBarrierModel (.get ThreatModelProfiles gc-tricolor-barrier))
          (cons SafepointHandshakeModel (.get ThreatModelProfiles gc-safepoint-handshake))
          (cons EpochReclamationModel (.get ThreatModelProfiles parallel-epoch-reclamation))
          (cons WorkStealingDequeModel (.get ThreatModelProfiles parallel-work-stealing))
          (cons StructuredCancelModel (.get ThreatModelProfiles concurrency-structured-cancel)))))))
