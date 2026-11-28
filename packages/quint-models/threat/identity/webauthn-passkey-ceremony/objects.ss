;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; WebAuthn / FIDO2 Passkey Ceremony threat model.
;;; Co-located Yuanxu unit: single source of truth alongside WebAuthnPasskeyCeremony.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export WebAuthnPasskeyCeremonyModel)

(.def (WebAuthnPasskeyCeremonyModel @ AuthorityCurrentnessModel)
  identity: 'threat.identity.webauthn-passkey-ceremony
  family: 'threat.identity.webauthn-passkey-ceremony
  title: "WebAuthn / FIDO2 Passkey Ceremony, RP-ID Binding & signCount Clone Detection"
  subdomain: 'quint.threat.identity
  papers:
  '(("W3C WebAuthn Working Group (W3C Recommendation, Level 3)"
     "Web Authentication: An API for accessing Public Key Credentials — RP-ID origin binding and signCount verification.")
    ("M. Barbosa, A. Boldyreva, S. Chen & B. Warinschi (CRYPTO 2021)"
     "Provable Security Analysis of FIDO2.")
    ("C. Jacomme & S. Kremer (ACM TOPS 2021)"
     "An Extensive Formal Analysis of Multi-Factor Authentication Protocols."))
  quint-module: "webauthn_passkey_ceremony"
  quint-file: "WebAuthnPasskeyCeremony.qnt"
  domain-dir: "threat/identity/webauthn-passkey-ceremony"
  rules:
  '((rpid-origin-binding WEBAUTHN-RPID-ORIGIN quint)
    (challenge-single-use WEBAUTHN-CHAL-ONCE quint)
    (signcount-monotonicity WEBAUTHN-SIGNCNT-MONO quint))
  dependencies:
  '((WEBAUTHN-RPID-ORIGIN source)
    (WEBAUTHN-RPID-ORIGIN profile)
    (WEBAUTHN-RPID-ORIGIN method)
    (WEBAUTHN-CHAL-ONCE source)
    (WEBAUTHN-CHAL-ONCE profile)
    (WEBAUTHN-CHAL-ONCE method)
    (WEBAUTHN-SIGNCNT-MONO source)
    (WEBAUTHN-SIGNCNT-MONO profile)
    (WEBAUTHN-SIGNCNT-MONO method))
  invariant: "Every accepted WebAuthn login binds to the exact RP origin, consumes a unique ceremony challenge once, and advances the authenticator signCount monotonically."
  limits: "Finite WebAuthn/FIDO2 ceremony abstraction; assumes honest browser origin reporting and does not model endpoint malware, COSE signature mathematics, or synced zero-counter passkeys.")
