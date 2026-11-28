;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; OAuth PAR + Crash-Safe Revocation Recovery threat model (RFC 9126 / RFC 7009).
;;; Co-located Yuanxu unit: single source of truth alongside OAuthRevocationRecovery.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export OAuthRevocationRecoveryModel)

(.def (OAuthRevocationRecoveryModel @ AuthorityCurrentnessModel)
  identity: 'threat.identity.oauth-revocation-recovery
  family: 'threat.identity.oauth-revocation-recovery
  title: "OAuth PAR Binding & Crash-Safe Durable Revocation Recovery"
  subdomain: 'quint.threat.identity
  papers:
  '(("T. Lodderstedt, B. Campbell, N. Sakimura, D. Tonge & F. Skokan (IETF RFC 9126, 2021)"
     "OAuth 2.0 Pushed Authorization Requests (PAR): authenticated pre-registration of authorization parameters.")
    ("T. Lodderstedt, S. Dronia & M. Scurtescu (IETF RFC 7009, 2013)"
     "OAuth 2.0 Token Revocation: durable sign-out intent across host crashes."))
  quint-module: "oauth_revocation_recovery"
  quint-file: "OAuthRevocationRecovery.qnt"
  domain-dir: "threat/identity/oauth-revocation-recovery"
  rules:
  '((par-request-binding OAUTH-PAR-BIND quint)
    (durable-revoke-intent OAUTH-REV-DURABLE quint))
  dependencies:
  '((OAUTH-PAR-BIND source)
    (OAUTH-PAR-BIND profile)
    (OAUTH-PAR-BIND method)
    (OAUTH-REV-DURABLE source)
    (OAUTH-REV-DURABLE profile)
    (OAUTH-REV-DURABLE method))
  invariant: "Token admission requires PAR binding, and once revocation intent is requested, crash-recovery never restores an active session."
  limits: "Finite PAR and crash-recovery state abstraction; does not model network partitions to RFC 7009 endpoints or filesystem fsync internals.")
