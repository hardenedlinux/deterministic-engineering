;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Multi-Party Shared Context Governance, Scope Lattice & Taint Isolation threat model.
;;; Co-located Yuanxu unit: single source of truth alongside SharedContextGovernance.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export SharedContextGovernanceModel)

(.def (SharedContextGovernanceModel @ AuthorityCurrentnessModel)
  identity: 'threat.zero-trust.shared-context-governance
  family: 'threat.zero-trust.shared-context-governance
  title: "Multi-Party Shared Context Governance, Scope Lattice, and Taint Isolation"
  subdomain: 'quint.threat.zero-trust
  papers:
  '(("D. E. Denning (CACM 1976)"
     "A Lattice Model of Secure Information Flow: scoped confidentiality boundaries and explicit declassification.")
    ("E. Debenedetti et al. (2025)"
     "Defeating Prompt Injections by Design (CaMeL): preventing untrusted shared-context taint from hijacking privileged tools."))
  quint-module: "shared_context_governance"
  quint-file: "SharedContextGovernance.qnt"
  domain-dir: "threat/zero-trust/shared-context-governance"
  rules:
  '((owner-only-scope-promotion SCG-OWNER-PROMOTE quint)
    (private-scope-isolation SCG-PRIVATE-SCOPE quint)
    (share-membership-current SCG-ACL-CURRENT quint)
    (multi-party-taint-gate SCG-TAINT-GATE quint))
  dependencies:
  '((SCG-OWNER-PROMOTE source)
    (SCG-OWNER-PROMOTE profile)
    (SCG-OWNER-PROMOTE method)
    (SCG-PRIVATE-SCOPE source)
    (SCG-PRIVATE-SCOPE profile)
    (SCG-PRIVATE-SCOPE method)
    (SCG-ACL-CURRENT source)
    (SCG-ACL-CURRENT profile)
    (SCG-ACL-CURRENT method)
    (SCG-TAINT-GATE source)
    (SCG-TAINT-GATE profile)
    (SCG-TAINT-GATE method))
  invariant: "Private context never leaks to peer principals, only owners with explicit declassification may widen private scope, revoked members never read via stale handles, and tainted multi-party shared context never drives tool execution without human gate approval."
  limits: "Finite two-principal scope-promotion, ACL-epoch revocation, and multi-party taint abstraction; does not model vector-embedding semantic leakage, encrypted group key agreement, or side-channel cache timing.")
