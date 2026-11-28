;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Zero Trust cross-tenant microsegmentation and egress mediation model.
;;; Co-located Yuanxu unit: single source of truth alongside MicrosegmentationEgress.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects AuthorityCurrentnessModel))
(export MicrosegmentationEgressModel)

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
  limits: "Finite 2-tenant egress mediation abstraction; does not model L3/L4 packet filtering, DNS tunneling, or kernel namespace escapes.")
