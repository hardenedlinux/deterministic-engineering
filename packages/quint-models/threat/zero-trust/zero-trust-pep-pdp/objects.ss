;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Zero Trust PEP/PDP separation model under concurrent policy updates and revocation.
;;; Co-located Yuanxu unit: single source of truth alongside ZeroTrustPepPdp.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects AuthorityCurrentnessModel))
(export ZeroTrustPepPdpModel)

(.def (ZeroTrustPepPdpModel @ AuthorityCurrentnessModel)
  identity: 'threat.zero-trust.zero-trust-pep-pdp
  family: 'threat.zero-trust.zero-trust-pep-pdp
  title: "Zero Trust PEP/PDP Split & Policy-Epoch Currentness"
  subdomain: 'quint.threat.zero-trust
  papers:
  '(("S. Rose, O. Borchert, S. Mitchell & S. Connelly (NIST SP 800-207, 2020)"
     "Zero Trust Architecture: Policy Engine (PE/PDP) and Policy Enforcement Point (PEP) trust separation.")
    ("R. Ward & B. Beyer (USENIX ;login: 2014)"
     "BeyondCorp: A New Approach to Enterprise Security — continuous policy re-evaluation without perimeter trust."))
  quint-module: "zero_trust_pep_pdp"
  quint-file: "ZeroTrustPepPdp.qnt"
  domain-dir: "threat/zero-trust/zero-trust-pep-pdp"
  rules:
  '((zt-pep-pdp-current ZT-PEP-CUR quint)
    (zt-pep-pdp-stale ZT-PEP-STALE quint))
  dependencies:
  '((ZT-PEP-CUR source)
    (ZT-PEP-CUR profile)
    (ZT-PEP-CUR method)
    (ZT-PEP-STALE source)
    (ZT-PEP-STALE profile)
    (ZT-PEP-STALE method))
  invariant: "PEP enforces an effect only when the PDP decision matches the current policy epoch and active non-revoked subject standing."
  limits: "Finite PEP/PDP policy-epoch abstraction; does not model transport cryptography, clock skew, or policy language semantics.")
