;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; OIDC Federation threat model (OIDC Core 1.0 §3.1.3.7 & §5.3.4 / RFC 7517 JWKS).
;;; Co-located Yuanxu unit: single source of truth alongside OidcFederation.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export OidcFederationModel
        SubSubstitutionCountermodel
        AzpBypassCountermodel
        JwksRefreshStormCountermodel)

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
  quint-imports:
  '(("authority_currentness" "../../zero-trust/authority-currentness/AuthorityCurrentness"))
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
  parameters: '()
  state:
  '((jwksEpoch "int" "1")
    (jwksRefreshes "int" "0")
    (jwksCooldown "bool" "false")
    (idTokenVerified "bool" "false")
    (idTokenSub "int" "0")
    (multiAud "bool" "false")
    (azpMatchesClient "bool" "false")
    (userInfoFetched "bool" "false")
    (userInfoSub "int" "0")
    (admitted "bool" "false"))
  guards:
  '((multi-aud-azp-binding (or (not isMultiAud) azpOk))
    (userinfo-sub-binding (and (. h idTokenVerified) (= uiSub (. h idTokenSub))))
    (jwks-refresh-cooldown (and (not (. h jwksCooldown)) (< (. h jwksRefreshes) 2))))
  transitions:
  '((verifyIdTokenAs
      (action verifyIdTokenAs ((sub "int")
                               (isMultiAud "bool")
                               (azpOk "bool")
                               (algSafe "bool"))
              "bool"
        (if (and (not (. h idTokenVerified))
                 algSafe
                 (guard multi-aud-azp-binding (or (not isMultiAud) azpOk)))
          (set-h (idTokenVerified #t)
                 (idTokenSub sub)
                 (multiAud isMultiAud)
                 (azpMatchesClient azpOk))
          (keep-h))))
    (verifyIdToken
      (action verifyIdToken ()
        (nondet ((sub (set 1 2))
                 (isMultiAud (set #f #t))
                 (azpOk (set #f #t))
                 (algSafe (set #f #t)))
          (call verifyIdTokenAs sub isMultiAud azpOk algSafe))))
    (fetchUserInfoAndAdmitAs
      (action fetchUserInfoAndAdmitAs ((uiSub "int")) "bool"
        (if (and (. h idTokenVerified)
                 (not (. h admitted))
                 (guard userinfo-sub-binding (= uiSub (. h idTokenSub))))
          (set-h (userInfoFetched #t)
                 (userInfoSub uiSub)
                 (admitted #t))
          (keep-h))))
    (fetchUserInfoAndAdmit
      (action fetchUserInfoAndAdmit ()
        (nondet ((uiSub (set 1 2)))
          (call fetchUserInfoAndAdmitAs uiSub))))
    (refreshJwks
      (action refreshJwks ()
        (if (guard jwks-refresh-cooldown
                   (and (not (. h jwksCooldown)) (< (. h jwksRefreshes) 2)))
          (set-h (jwksEpoch (+ (. h jwksEpoch) 1))
                 (jwksRefreshes (+ (. h jwksRefreshes) 1))
                 (jwksCooldown #t))
          (keep-h))))
    (cooldownTick
      (action cooldownTick ()
        (if (. h jwksCooldown)
          (set-h (jwksCooldown #f))
          (keep-h))))
    (step
      (action step ()
        (any verifyIdToken fetchUserInfoAndAdmit refreshJwks cooldownTick))))
  safety:
  '(and (or (not (. h admitted))
            (and (. h idTokenVerified)
                 (= (. h userInfoSub) (. h idTokenSub))
                 (or (not (. h multiAud)) (. h azpMatchesClient))))
        (<= (. h jwksRefreshes) 2))
  traces:
  '((checkSafe
      (action checkSafe ()
        (all (assert safety) (keep-h))))
    (checkUnsafe
      (action checkUnsafe ()
        (all (assert (not safety)) (keep-h))))
    (validOidcFederationTest
      (run validOidcFederationTest
        (then init (call verifyIdTokenAs 1 #t #t #t) (call fetchUserInfoAndAdmitAs 1)
              (all (assert (. h admitted))
                   (assert safety)
                   (keep-h)))))
    (mismatchedUserInfoSubRejectedTest
      (run mismatchedUserInfoSubRejectedTest
        (then init (call verifyIdTokenAs 1 #f #f #t) (call fetchUserInfoAndAdmitAs 2)
              (all (assert (not (. h admitted)))
                   (assert safety)
                   (keep-h)))))
    (multiAudMissingAzpRejectedTest
      (run multiAudMissingAzpRejectedTest
        (then init (call verifyIdTokenAs 1 #t #f #t)
              (all (assert (not (. h idTokenVerified)))
                   (assert safety)
                   (keep-h)))))
    (jwksCooldownEnforcedTest
      (run jwksCooldownEnforcedTest
        (then init refreshJwks refreshJwks
              (all (assert (= (. h jwksRefreshes) 1))
                   (assert safety)
                   (keep-h)))))
    (subSubstitutionCountermodelTest
      (run subSubstitutionCountermodelTest
        (then init (call verifyIdTokenAs 1 #f #f #t)
              (call fetchUserInfoNoSubCheck 2) checkUnsafe))))
  countermodels:
  (list SubSubstitutionCountermodel
        AzpBypassCountermodel
        JwksRefreshStormCountermodel)
  limits: "Finite OIDC Federation protocol abstraction; does not model RSA/ECDSA/EdDSA signature mathematics, TLS certificate validation, or IdP internal key storage.")

(.def (SubSubstitutionCountermodel @ OidcFederationModel)
  identity: 'threat.identity.oidc-federation.sub-substitution
  dropped-guard: 'userinfo-sub-binding
  step-action: "stepSubSubstitution"
  derive-from-transition: 'fetchUserInfoAndAdmitAs
  derive-action-name: 'fetchUserInfoNoSubCheck
  derive-step-call: '(nondet ((uiSub (set 1 2)))
                       (call fetchUserInfoNoSubCheck uiSub))
  expected-itf-predicate: "h.admitted == true and h.userInfoSub != h.idTokenSub")

(.def (AzpBypassCountermodel @ OidcFederationModel)
  identity: 'threat.identity.oidc-federation.azp-bypass
  dropped-guard: 'multi-aud-azp-binding
  step-action: "stepAzpBypass"
  derive-from-transition: 'verifyIdTokenAs
  derive-action-name: 'verifyIdTokenNoAzp
  derive-step-call: '(nondet ((sub (set 1 2))
                              (isMultiAud (set #f #t))
                              (azpOk (set #f #t))
                              (algSafe (set #f #t)))
                       (call verifyIdTokenNoAzp sub isMultiAud azpOk algSafe))
  expected-itf-predicate: "h.admitted == true and h.multiAud == true and not(h.azpMatchesClient)")

(.def (JwksRefreshStormCountermodel @ OidcFederationModel)
  identity: 'threat.identity.oidc-federation.jwks-refresh-storm
  dropped-guard: 'jwks-refresh-cooldown
  step-action: "stepJwksStorm"
  derive-from-transition: 'refreshJwks
  derive-action-name: 'refreshJwksUnthrottled
  expected-itf-predicate: "h.jwksRefreshes > 2")
