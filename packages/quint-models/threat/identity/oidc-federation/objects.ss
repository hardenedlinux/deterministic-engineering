;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; OIDC Federation threat model (OIDC Core 1.0 §3.1.3.7 & §5.3.4 / RFC 7517 JWKS).
;;; Co-located Yuanxu unit: single source of truth alongside OidcFederation.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export OidcFederationModel)

(.def (OidcFederationModel @ AuthorityCurrentnessModel)
  identity: 'threat.identity.oidc-federation
  family: 'threat.identity.oidc-federation
  title: "OpenID Connect (OIDC) Federation, azp/sub Binding & JWKS Cooldown"
  subdomain: 'quint.threat.identity
  papers:
  '(("N. Sakimura, J. Bradley, M. Jones, B. de Medeiros & C. Mortimore (OpenID Foundation 2014)"
     "OpenID Connect Core 1.0: §3.1.3.7 ID Token azp validation and §5.3.4 UserInfo sub equality.")
    ("D. Fett, R. Küsters & G. Schmitz (IEEE S&P 2017)"
     "The Web SSO Standard OpenID Connect: In-depth Formal Security Analysis and Security Guidelines."))
  quint-module: "oidc_federation"
  quint-file: "OidcFederation.qnt"
  domain-dir: "threat/identity/oidc-federation"
  rules:
  '((oidc-azp-binding OIDC-AZP-BIND quint)
    (oidc-sub-binding OIDC-SUB-BIND quint)
    (oidc-jwks-cooldown OIDC-JWKS-COOL quint))
  dependencies:
  '((OIDC-AZP-BIND source)
    (OIDC-AZP-BIND profile)
    (OIDC-AZP-BIND method)
    (OIDC-SUB-BIND source)
    (OIDC-SUB-BIND profile)
    (OIDC-SUB-BIND method)
    (OIDC-JWKS-COOL source)
    (OIDC-JWKS-COOL profile)
    (OIDC-JWKS-COOL method))
  invariant: "Admitted OIDC sessions require asymmetric ID-token verification, matching azp on multi-audience tokens, exact UserInfo sub equality with the verified ID token, and bounded JWKS refresh cooldown."
  limits: "Finite OIDC Federation protocol abstraction; does not model RSA/ECDSA/EdDSA signature mathematics, TLS certificate validation, or IdP internal key storage.")
