;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Zero Trust cross-tenant microsegmentation and egress mediation model.
;;; Co-located Yuanxu unit: single source of truth alongside MicrosegmentationEgress.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects AuthorityCurrentnessModel))
(export MicrosegmentationEgressModel
        BypassSidecarCountermodel
        BypassTenantPolicyCountermodel)

(.def (MicrosegmentationEgressModel @ AuthorityCurrentnessModel)
  identity: 'threat.zero-trust.microsegmentation-egress
  family: 'threat.zero-trust.microsegmentation-egress
  title: "Zero Trust Microsegmentation & Cross-Tenant Egress Mediation"
  subdomain: 'quint.threat.zero-trust
  papers:
  '(("S. Rose, O. Borchert, S. Mitchell & S. Connelly (NIST SP 800-207, 2020)"
     "Zero Trust Architecture: micro-perimeter sidecar PEP mediation and assume-breach containment.")
    ("R. Chandramouli (NIST SP 800-204A / 204B, 2020-2021)"
     "Building Secure Microservices-based Applications Using Service-Mesh Architecture."))
  quint-module: "microsegmentation_egress"
  quint-file: "MicrosegmentationEgress.qnt"
  domain-dir: "threat/zero-trust/microsegmentation-egress"
  quint-imports:
  '(("authority_currentness" "../authority-currentness/AuthorityCurrentness"))
  rules:
  '((zt-egress-mediate ZT-EGRESS-MED quint)
    (zt-egress-bypass ZT-EGRESS-BYP quint))
  dependencies:
  '((ZT-EGRESS-MED source)
    (ZT-EGRESS-MED profile)
    (ZT-EGRESS-MED method)
    (ZT-EGRESS-BYP source)
    (ZT-EGRESS-BYP profile)
    (ZT-EGRESS-BYP method))
  invariant: "Active egress flows require attested non-quarantined sidecar mediation and explicit cross-tenant authorization when crossing tenant boundaries."
  parameters: '()
  state:
  '((tenantId "int" "1")
    (crossTenantAllowed "bool" "false")
    (sidecarAttested "bool" "true")
    (quarantined "bool" "false")
    (delivered "int" "0")
    (activeFlowDest "int" "0"))
  guards:
  '((sidecar-attestation (and (. h sidecarAttested) (not (. h quarantined))))
    (tenant-policy (or (= dest (. h tenantId)) (. h crossTenantAllowed))))
  transitions:
  '((mediateEgressAs
      (action mediateEgressAs ((dest "int")) "bool"
        (if (and (guard sidecar-attestation
                        (and (. h sidecarAttested) (not (. h quarantined))))
                 (guard tenant-policy
                        (or (= dest (. h tenantId)) (. h crossTenantAllowed))))
          (set-h (delivered (+ (. h delivered) 1))
                 (activeFlowDest dest))
          (keep-h))))
    (mediateEgress
      (action mediateEgress ()
        (nondet ((dest (set 1 2)))
          (call mediateEgressAs dest))))
    (allowCrossTenant
      (action allowCrossTenant ()
        (set-h (crossTenantAllowed #t))))
    (denyCrossTenant
      (action denyCrossTenant ()
        (set-h (crossTenantAllowed #f)
               (activeFlowDest (if (!= (. h activeFlowDest) (. h tenantId))
                                 0
                                 (. h activeFlowDest))))))
    (loseAttestation
      (action loseAttestation ()
        (set-h (sidecarAttested #f)
               (activeFlowDest 0))))
    (quarantineWorkload
      (action quarantineWorkload ()
        (set-h (quarantined #t)
               (activeFlowDest 0))))
    (step
      (action step ()
        (any mediateEgress allowCrossTenant denyCrossTenant
             loseAttestation quarantineWorkload))))
  safety:
  '(or (= (. h activeFlowDest) 0)
       (and (. h sidecarAttested)
            (not (. h quarantined))
            (or (= (. h activeFlowDest) (. h tenantId))
                (. h crossTenantAllowed))))
  traces:
  '((checkSafe
      (action checkSafe ()
        (all (assert safety) (keep-h))))
    (checkBlocked
      (action checkBlocked ()
        (all (assert (= (. h delivered) 0))
             (assert safety)
             (keep-h))))
    (checkUnsafe
      (action checkUnsafe ()
        (all (assert (not safety)) (keep-h))))
    (sameTenantAllowedTest
      (run sameTenantAllowedTest
        (then init (call mediateEgressAs 1)
              (all (assert (= (. h delivered) 1))
                   (assert (= (. h activeFlowDest) 1))
                   (assert safety)
                   (keep-h)))))
    (crossTenantBlockedByDefaultTest
      (run crossTenantBlockedByDefaultTest
        (then init (call mediateEgressAs 2) checkBlocked)))
    (quarantineBlocksEgressTest
      (run quarantineBlocksEgressTest
        (then init quarantineWorkload (call mediateEgressAs 1) checkBlocked)))
    (bypassSidecarLeaksTest
      (run bypassSidecarLeaksTest
        (then init quarantineWorkload (call mediateEgressBypass 1) checkUnsafe)))
    (bypassTenantPolicyLeaksTest
      (run bypassTenantPolicyLeaksTest
        (then init (call mediateEgressNoPolicy 2) checkUnsafe))))
  countermodels:
  (list BypassSidecarCountermodel
        BypassTenantPolicyCountermodel)
  limits: "Finite 2-tenant egress mediation abstraction; does not model L3/L4 packet filtering, DNS tunneling, or kernel namespace escapes.")

(.def (BypassSidecarCountermodel @ MicrosegmentationEgressModel)
  identity: 'threat.zero-trust.microsegmentation-egress.bypass-sidecar
  dropped-guard: 'sidecar-attestation
  step-action: "stepBypassSidecar"
  derive-from-transition: 'mediateEgressAs
  derive-action-name: 'mediateEgressBypass
  derive-step-call: '(nondet ((dest (set 1 2)))
                       (call mediateEgressBypass dest))
  expected-itf-predicate: "h.activeFlowDest > 0 and (h.quarantined == true or not(h.sidecarAttested))")

(.def (BypassTenantPolicyCountermodel @ MicrosegmentationEgressModel)
  identity: 'threat.zero-trust.microsegmentation-egress.bypass-tenant-policy
  dropped-guard: 'tenant-policy
  step-action: "stepBypassTenantPolicy"
  derive-from-transition: 'mediateEgressAs
  derive-action-name: 'mediateEgressNoPolicy
  derive-step-call: '(nondet ((dest (set 1 2)))
                       (call mediateEgressNoPolicy dest))
  expected-itf-predicate: "h.activeFlowDest > 0 and h.activeFlowDest != h.tenantId and not(h.crossTenantAllowed)")
