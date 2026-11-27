;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; OAuth 2.1 token lifecycle threat model (RFC 9700 / PKCE S256 / RTR / Epoch Currency).
;;; Co-located Yuanxu unit: single source of truth alongside OAuthTokenLifecycle.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export OAuthTokenLifecycleModel)

(.def (OAuthTokenLifecycleModel @ AuthorityCurrentnessModel)
  identity: 'threat.identity.oauth-token-lifecycle
  family: 'threat.identity.oauth-token-lifecycle
  title: "OAuth 2.1 Token Lifecycle, PKCE Single-Use & Refresh Epoch Currency"
  subdomain: 'quint.threat.identity
  papers:
  '(("T. Lodderstedt, J. Bradley, A. Labunets & D. Fett (IETF RFC 9700, 2025)"
     "Best Current Practice for OAuth 2.0 Security: PKCE, single-use authorization codes, and refresh token rotation.")
    ("D. Fett, R. Küsters & G. Schmitz (ACM CCS 2016)"
     "A Comprehensive Formal Security Analysis of OAuth 2.0."))
  quint-module: "oauth_token_lifecycle"
  quint-file: "OAuthTokenLifecycle.qnt"
  domain-dir: "threat/identity/oauth-token-lifecycle"
  rules:
  '((oauth-code-once OAUTH-CODE-ONCE quint)
    (oauth-refresh-epoch OAUTH-REF-EPOCH quint)
    (oauth-scope-mono OAUTH-SCOPE-MONO quint))
  dependencies:
  '((OAUTH-CODE-ONCE source)
    (OAUTH-CODE-ONCE profile)
    (OAUTH-CODE-ONCE method)
    (OAUTH-REF-EPOCH source)
    (OAUTH-REF-EPOCH profile)
    (OAUTH-REF-EPOCH method)
    (OAUTH-SCOPE-MONO source)
    (OAUTH-SCOPE-MONO profile)
    (OAUTH-SCOPE-MONO method))
  invariant: "Authorization codes are single-use with PKCE+nonce, refresh never resurrects a signed-out/revoked vault entry, and refreshed scopes never escalate beyond granted scopes."
  limits: "Finite OAuth 2.1 lifecycle abstraction; does not model TLS, JWT signature cryptography, or IdP internal storage.")
