;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; WebAuthn / FIDO2 Passkey Ceremony threat model.
;;; Grounded in W3C WebAuthn Level 3, Barbosa et al. (CRYPTO 2021, Provable Security
;;; Analysis of FIDO2), and Jacomme & Kremer (IEEE S&P / ACM TOPS 2021):
;;; enforces RP-ID origin binding against MitM phishing proxies, single-use ceremony
;;; challenges, and monotonic authenticator signCount clone detection.
;;; Emergent safety (zero synthetic unsafe flag); all 3 countermodels auto-derived via (guard ...).
(import :clan/poo/object
        (only-in "../authority-currentness/objects.ss" AuthorityCurrentnessModel))
(export WebAuthnPasskeyCeremonyModel
        PhishingOriginRelayCountermodel
        ChallengeReplayCountermodel
        ClonedSignCountCountermodel)

(.def (WebAuthnPasskeyCeremonyModel @ AuthorityCurrentnessModel)
  identity: 'threat.webauthn-passkey-ceremony
  family: 'threat.webauthn-passkey-ceremony
  quint-module: "webauthn_passkey_ceremony"
  quint-file: "WebAuthnPasskeyCeremony.qnt"
  domain-dir: "threat/webauthn-passkey-ceremony"
  quint-imports: '(("authority_currentness" "../authority-currentness/AuthorityCurrentness"))
  rules: '((rpid-origin-binding WEBAUTHN-RPID-ORIGIN quint)
           (challenge-single-use WEBAUTHN-CHAL-ONCE quint)
           (signcount-monotonicity WEBAUTHN-SIGNCNT-MONO quint))
  dependencies: '((WEBAUTHN-RPID-ORIGIN source) (WEBAUTHN-RPID-ORIGIN profile) (WEBAUTHN-RPID-ORIGIN method)
                  (WEBAUTHN-CHAL-ONCE source) (WEBAUTHN-CHAL-ONCE profile) (WEBAUTHN-CHAL-ONCE method)
                  (WEBAUTHN-SIGNCNT-MONO source) (WEBAUTHN-SIGNCNT-MONO profile) (WEBAUTHN-SIGNCNT-MONO method))
  invariant: "Every accepted WebAuthn login binds to the exact RP origin, consumes a unique ceremony challenge once, and advances the authenticator signCount monotonically."
  parameters: '()
  state: '((rpOrigin "int" "1")
           (activeChallenge "int" "0")
           (nextChallenge "int" "1")
           (consumedChallenges "Set[int]" "Set()")
           (rpStoredCounter "int" "0")
           (prevStoredCounter "int" "0")
           (lastAcceptedOrigin "int" "1")
           (lastAcceptedCounter "int" "1")
           (totalLogins "int" "0"))
  guards: '((rpid-origin-binding (= origin (. h rpOrigin)))
            (challenge-single-use (and (> ch 0) (= ch (. h activeChallenge)) (not (contains (. h consumedChallenges) ch))))
            (signcount-monotonicity (> cnt (. h rpStoredCounter))))
  transitions:
  '((issueChallenge
      (action issueChallenge ()
        (if (and (= (. h activeChallenge) 0) (<= (. h nextChallenge) 3))
          (set-h (activeChallenge (. h nextChallenge))
                 (nextChallenge (+ (. h nextChallenge) 1)))
          (keep-h))))
    (rpVerifyAssertion
      (action rpVerifyAssertion ((origin "int") (ch "int") (cnt "int")) "bool"
        (if (and (guard rpid-origin-binding (= origin (. h rpOrigin)))
                 (guard challenge-single-use (and (> ch 0) (= ch (. h activeChallenge)) (not (contains (. h consumedChallenges) ch))))
                 (guard signcount-monotonicity (> cnt (. h rpStoredCounter))))
          (set-h (consumedChallenges (union (. h consumedChallenges) (set ch)))
                 (activeChallenge 0)
                 (prevStoredCounter (. h rpStoredCounter))
                 (rpStoredCounter (if (> cnt (. h rpStoredCounter)) cnt (. h rpStoredCounter)))
                 (lastAcceptedOrigin origin)
                 (lastAcceptedCounter cnt)
                 (totalLogins (+ (. h totalLogins) 1)))
          (keep-h))))
    (honestSignAndVerify
      (action honestSignAndVerify ()
        (if (> (. h activeChallenge) 0)
          (call rpVerifyAssertion 1 (. h activeChallenge) (+ (. h rpStoredCounter) 1))
          (keep-h))))
    (phishingRelayAttempt
      (action phishingRelayAttempt ()
        (if (> (. h activeChallenge) 0)
          (call rpVerifyAssertion 2 (. h activeChallenge) (+ (. h rpStoredCounter) 1))
          (keep-h))))
    (replayOldAssertion
      (action replayOldAssertion ()
        (nondet ((c (set 1 2 3)))
          (if (contains (. h consumedChallenges) c)
            (call rpVerifyAssertion 1 c (+ (. h rpStoredCounter) 1))
            (keep-h)))))
    (clonedTokenAttempt
      (action clonedTokenAttempt ()
        (if (and (> (. h activeChallenge) 0) (> (. h rpStoredCounter) 0))
          (call rpVerifyAssertion 1 (. h activeChallenge) (. h rpStoredCounter))
          (keep-h))))
    (step
      (action step ()
        (any issueChallenge honestSignAndVerify phishingRelayAttempt replayOldAssertion clonedTokenAttempt))))
  safety:
  '(or (= (. h totalLogins) 0)
       (and (= (. h lastAcceptedOrigin) (. h rpOrigin))
            (= (. h totalLogins) (size (. h consumedChallenges)))
            (> (. h lastAcceptedCounter) (. h prevStoredCounter))))
  traces:
  '((checkSafe (action checkSafe () (all (assert safety) (keep-h))))
    (checkUnsafe (action checkUnsafe () (all (assert (not safety)) (keep-h))))
    (validPasskeyLoginTest
      (run validPasskeyLoginTest
        (then init issueChallenge honestSignAndVerify
              (all (assert (= (. h totalLogins) 1)) (assert (= (. h rpStoredCounter) 1)) (assert safety) (keep-h)))))
    (phishingOriginBlockedTest
      (run phishingOriginBlockedTest
        (then init issueChallenge phishingRelayAttempt
              (all (assert (= (. h totalLogins) 0)) (assert safety) (keep-h)))))
    (clonedTokenBlockedTest
      (run clonedTokenBlockedTest
        (then init issueChallenge honestSignAndVerify issueChallenge clonedTokenAttempt
              (all (assert (= (. h totalLogins) 1)) (assert safety) (keep-h)))))
    (phishingRelayCountermodelTest
      (run phishingRelayCountermodelTest
        (then init issueChallenge (call rpVerifyNoOrigin 2 1 1) checkUnsafe)))
    (challengeReplayCountermodelTest
      (run challengeReplayCountermodelTest
        (then init issueChallenge honestSignAndVerify (call rpVerifyNoChallenge 1 1 2) checkUnsafe)))
    (clonedSignCountCountermodelTest
      (run clonedSignCountCountermodelTest
        (then init issueChallenge honestSignAndVerify issueChallenge (call rpVerifyNoSignCount 1 2 1) checkUnsafe))))
  countermodels: (list PhishingOriginRelayCountermodel ChallengeReplayCountermodel ClonedSignCountCountermodel)
  limits: "Finite WebAuthn/FIDO2 ceremony abstraction; assumes honest browser origin reporting and does not model endpoint malware, COSE signature mathematics, or synced zero-counter passkeys.")

(.def (PhishingOriginRelayCountermodel @ WebAuthnPasskeyCeremonyModel)
  identity: 'threat.webauthn-passkey-ceremony.phishing-origin-relay
  dropped-guard: 'rpid-origin-binding
  step-action: "stepPhishingOriginRelay"
  derive-from-transition: 'rpVerifyAssertion
  derive-action-name: 'rpVerifyNoOrigin
  derive-step-call: '(if (> (. h activeChallenge) 0)
                       (call rpVerifyNoOrigin 2 (. h activeChallenge) (+ (. h rpStoredCounter) 1))
                       (keep-h))
  expected-itf-predicate: "h.totalLogins >= 1 and h.lastAcceptedOrigin != h.rpOrigin")

(.def (ChallengeReplayCountermodel @ WebAuthnPasskeyCeremonyModel)
  identity: 'threat.webauthn-passkey-ceremony.challenge-replay
  dropped-guard: 'challenge-single-use
  step-action: "stepChallengeReplay"
  derive-from-transition: 'rpVerifyAssertion
  derive-action-name: 'rpVerifyNoChallenge
  derive-step-call: '(nondet ((c (set 1 2 3)))
                       (if (contains (. h consumedChallenges) c)
                         (call rpVerifyNoChallenge 1 c (+ (. h rpStoredCounter) 1))
                         (keep-h)))
  expected-itf-predicate: "h.totalLogins > size(h.consumedChallenges)")

(.def (ClonedSignCountCountermodel @ WebAuthnPasskeyCeremonyModel)
  identity: 'threat.webauthn-passkey-ceremony.cloned-signcount
  dropped-guard: 'signcount-monotonicity
  step-action: "stepClonedSignCount"
  derive-from-transition: 'rpVerifyAssertion
  derive-action-name: 'rpVerifyNoSignCount
  derive-step-call: '(if (and (> (. h activeChallenge) 0) (> (. h rpStoredCounter) 0))
                       (call rpVerifyNoSignCount 1 (. h activeChallenge) (. h rpStoredCounter))
                       (keep-h))
  expected-itf-predicate: "h.totalLogins >= 2 and h.lastAcceptedCounter <= h.prevStoredCounter")
