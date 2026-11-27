;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; RFC 8693 On-Behalf-Of (OBO) Delegated Agent Authorization & RFC 9470 Step-Up Freshness threat model.
;;; Co-located Yuanxu unit: single source of truth alongside DelegatedAgentAuthz.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export DelegatedAgentAuthzModel)

(.def (DelegatedAgentAuthzModel @ AuthorityCurrentnessModel)
  identity: 'threat.identity.delegated-agent-authz
  family: 'threat.identity.delegated-agent-authz
  title: "RFC 8693 Delegated Agent Authorization (OBO) & RFC 9470 Step-Up Freshness"
  subdomain: 'quint.threat.identity
  papers:
  '(("M. Jones, A. Nadalin, B. Campbell, J. Bradley & C. Mortimore (IETF RFC 8693, 2020)"
     "OAuth 2.0 Token Exchange: On-Behalf-Of delegation, actor provenance claims, and monotonic scope attenuation.")
    ("V. Bertocci & B. Campbell (IETF RFC 9470, 2023)"
     "OAuth 2.0 Step-Up Authentication Challenge Protocol: fresh human verification for privileged operations."))
  quint-module: "delegated_agent_authz"
  quint-file: "DelegatedAgentAuthz.qnt"
  domain-dir: "threat/identity/delegated-agent-authz"
  rules:
  '((obo-scope-attenuation OBO-SCOPE-ATTEN quint)
    (obo-actor-provenance OBO-ACT-PROVENANCE quint)
    (obo-revocation-currency OBO-EPOCH-REVOKE quint)
    (step-up-verified-floor STEPUP-VERIFIED-FLOOR quint))
  dependencies:
  '((OBO-SCOPE-ATTEN source)
    (OBO-SCOPE-ATTEN profile)
    (OBO-SCOPE-ATTEN method)
    (OBO-ACT-PROVENANCE source)
    (OBO-ACT-PROVENANCE profile)
    (OBO-ACT-PROVENANCE method)
    (OBO-EPOCH-REVOKE source)
    (OBO-EPOCH-REVOKE profile)
    (OBO-EPOCH-REVOKE method)
    (STEPUP-VERIFIED-FLOOR source)
    (STEPUP-VERIFIED-FLOOR profile)
    (STEPUP-VERIFIED-FLOOR method))
  invariant: "Delegated agent tokens never amplify human scope, never impersonate direct human authority on human-only gates, fail closed immediately on human session revocation, and privileged operations require verified identity plus fresh step-up authentication."
  limits: "Finite RFC 8693 OBO delegation and RFC 9470 step-up abstraction; does not model JWT signature verification, multi-hop nested act arrays beyond depth 1, or IdP MFA phishing resistance.")
