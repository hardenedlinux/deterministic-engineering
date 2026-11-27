;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Multi-Tenant Isolation, Tenant-Bound Authorization & Offline Outbox Pinning threat model.
;;; Co-located Yuanxu unit: single source of truth alongside MultiTenantIsolation.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export MultiTenantIsolationModel)

(.def (MultiTenantIsolationModel @ AuthorityCurrentnessModel)
  identity: 'threat.zero-trust.multi-tenant-isolation
  family: 'threat.zero-trust.multi-tenant-isolation
  title: "Multi-Tenant Authorization Isolation & Tenant-Pinned Outbox Continuity"
  subdomain: 'quint.threat.zero-trust
  papers:
  '(("S. Rose, O. Borchert, S. Mitchell & S. Connelly (NIST SP 800-207, 2020)"
     "Zero Trust Architecture: continuous per-tenant authorization, membership revocation, and resource scoping.")
    ("J. W. Cutler et al. (OOPSLA 2024)"
     "Cedar: A Language for Expressive, Fast, Safe, and Analyzable Authorization for multi-tenant policies."))
  quint-module: "multi_tenant_isolation"
  quint-file: "MultiTenantIsolation.qnt"
  domain-dir: "threat/zero-trust/multi-tenant-isolation"
  rules:
  '((tenant-resource-match MT-RESOURCE-BIND quint)
    (tenant-membership-current MT-EPOCH-CURRENT quint)
    (outbox-tenant-binding MT-OUTBOX-PIN quint))
  dependencies:
  '((MT-RESOURCE-BIND source)
    (MT-RESOURCE-BIND profile)
    (MT-RESOURCE-BIND method)
    (MT-EPOCH-CURRENT source)
    (MT-EPOCH-CURRENT profile)
    (MT-EPOCH-CURRENT method)
    (MT-OUTBOX-PIN source)
    (MT-OUTBOX-PIN profile)
    (MT-OUTBOX-PIN method))
  invariant: "Tenant-scoped tickets never enforce against a foreign tenant resource or after tenant membership revocation, and queued offline outbox items never flush into a different active tenant."
  limits: "Finite two-tenant authorization, revocation epoch, and offline outbox pinning abstraction; does not model database row-level security engines, tenant KMS key rotation, or side-channel microarchitectural leaks.")
