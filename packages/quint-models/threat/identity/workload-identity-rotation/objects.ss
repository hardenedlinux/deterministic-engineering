;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Zero Trust short-lived workload identity (SVID) rotation and emergency revocation.
;;; Co-located Yuanxu unit: single source of truth alongside WorkloadIdentityRotation.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export WorkloadIdentityRotationModel)

(.def (WorkloadIdentityRotationModel @ AuthorityCurrentnessModel)
  identity: 'threat.identity.workload-identity-rotation
  family: 'threat.identity.workload-identity-rotation
  title: "Short-Lived Workload Identity (SVID) Rotation & Revocation Precedence"
  subdomain: 'quint.threat.identity
  papers:
  '(("CNCF SPIFFE Specification Working Group"
     "SPIFFE Verifiable Identity Document (SVID) & Workload API: overlapping generation rotation vs. immediate revocation.")
    ("S. Rose, O. Borchert, S. Mitchell & S. Connelly (NIST SP 800-207, 2020)"
     "Zero Trust Architecture: short-lived workload credentials and emergency revocation precedence."))
  quint-module: "workload_identity_rotation"
  quint-file: "WorkloadIdentityRotation.qnt"
  domain-dir: "threat/identity/workload-identity-rotation"
  rules:
  '((zt-svid-rotate ZT-SVID-ROT quint)
    (zt-svid-revoked-grace ZT-SVID-GRACE quint))
  dependencies:
  '((ZT-SVID-ROT source)
    (ZT-SVID-ROT profile)
    (ZT-SVID-ROT method)
    (ZT-SVID-GRACE source)
    (ZT-SVID-GRACE profile)
    (ZT-SVID-GRACE method))
  invariant: "Emergency revocation overrides any overlap/TTL window; no active workload session runs on a revoked or expired credential generation."
  limits: "Finite SVID generation-rotation abstraction; does not model X.509/JWT cryptography, clock drift, or CRL/OCSP transport latency.")
