;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; RFC 8693 On-Behalf-Of (OBO) Delegated Agent Authorization & RFC 9470 Step-Up Freshness threat model.
;;; Co-located Yuanxu unit: single source of truth alongside DelegatedAgentAuthz.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export DelegatedAgentAuthzModel
        OboScopeAmplificationCountermodel
        OboActorImpersonationCountermodel
        OboZombieRevokedDelegationCountermodel
        UnverifiedStepUpBypassCountermodel)

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
  quint-imports:
  '(("authority_currentness" "../../zero-trust/authority-currentness/AuthorityCurrentness"))
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
  parameters: '()
  state:
  '((humanAuthEpoch "int" "1")
    (humanSignedIn "bool" "true")
    (humanScopeLevel "int" "2")
    (emailVerified "bool" "true")
    (stepUpFresh "bool" "false")
    (delegatedActive "bool" "false")
    (delegatedEpoch "int" "0")
    (delegatedScopeLevel "int" "0")
    (humanGatesApproved "int" "0")
    (executedScopeLevel "int" "0")
    (scopeAmplified "bool" "false")
    (impersonatedHuman "bool" "false")
    (zombieDelegatedUse "bool" "false")
    (unverifiedPrivileged "bool" "false"))
  guards:
  '((obo-scope-attenuation (<= reqScope (. h humanScopeLevel)))
    (obo-actor-provenance (not isAgent))
    (obo-revocation-currency
      (and (. h humanSignedIn)
           (call epochCurrent (. h humanAuthEpoch) (. h delegatedEpoch))))
    (step-up-verified-floor
      (and (. h humanSignedIn)
           (. h emailVerified)
           (. h stepUpFresh))))
  transitions:
  '((performStepUp
      (action performStepUp ()
        (if (and (. h humanSignedIn) (. h emailVerified) (not (. h stepUpFresh)))
          (set-h (stepUpFresh #t))
          (keep-h))))
    (revokeHumanSession
      (action revokeHumanSession ()
        (if (and (. h humanSignedIn) (< (. h humanAuthEpoch) 3))
          (set-h (humanSignedIn #f)
                 (stepUpFresh #f)
                 (humanAuthEpoch (+ (. h humanAuthEpoch) 1)))
          (keep-h))))
    (reauthenticateHumanAs
      (action reauthenticateHumanAs ((verified "bool")) "bool"
        (if (and (not (. h humanSignedIn)) (< (. h humanAuthEpoch) 3))
          (set-h (humanSignedIn #t)
                 (emailVerified verified)
                 (stepUpFresh #f)
                 (humanAuthEpoch (+ (. h humanAuthEpoch) 1)))
          (keep-h))))
    (reauthenticateHuman
      (action reauthenticateHuman ()
        (nondet ((verified (set #t #f)))
          (call reauthenticateHumanAs verified))))
    (delegateToAgentAs
      (action delegateToAgentAs ((reqScope "int")) "bool"
        (if (and (. h humanSignedIn)
                 (not (. h delegatedActive))
                 (guard obo-scope-attenuation (<= reqScope (. h humanScopeLevel))))
          (set-h (delegatedActive #t)
                 (delegatedEpoch (. h humanAuthEpoch))
                 (delegatedScopeLevel reqScope)
                 (scopeAmplified (or (. h scopeAmplified) (> reqScope (. h humanScopeLevel)))))
          (keep-h))))
    (delegateToAgent
      (action delegateToAgent ()
        (nondet ((reqScope (set 1 2 3)))
          (call delegateToAgentAs reqScope))))
    (executeDelegated
      (action executeDelegated ()
        (if (and (. h delegatedActive)
                 (guard obo-revocation-currency
                        (and (. h humanSignedIn)
                             (call epochCurrent (. h humanAuthEpoch) (. h delegatedEpoch)))))
          (set-h (delegatedActive #f)
                 (executedScopeLevel (. h delegatedScopeLevel))
                 (zombieDelegatedUse
                   (or (. h zombieDelegatedUse)
                       (not (. h humanSignedIn))
                       (!= (. h humanAuthEpoch) (. h delegatedEpoch)))))
          (keep-h))))
    (approveHumanOnlyGateAs
      (action approveHumanOnlyGateAs ((isAgent "bool")) "bool"
        (if (and (. h humanSignedIn)
                 (< (. h humanGatesApproved) 3)
                 (or (not isAgent) (. h delegatedActive))
                 (guard obo-actor-provenance (not isAgent)))
          (set-h (humanGatesApproved (+ (. h humanGatesApproved) 1))
                 (impersonatedHuman (or (. h impersonatedHuman) isAgent)))
          (keep-h))))
    (approveHumanOnlyGate
      (action approveHumanOnlyGate ()
        (nondet ((isAgent (set #f #t)))
          (call approveHumanOnlyGateAs isAgent))))
    (executePrivilegedHuman
      (action executePrivilegedHuman ()
        (if (guard step-up-verified-floor
                   (and (. h humanSignedIn) (. h emailVerified) (. h stepUpFresh)))
          (set-h (stepUpFresh #f)
                 (unverifiedPrivileged
                   (or (. h unverifiedPrivileged)
                       (not (. h humanSignedIn))
                       (not (. h emailVerified))
                       (not (. h stepUpFresh)))))
          (keep-h))))
    (step
      (action step ()
        (any performStepUp revokeHumanSession reauthenticateHuman
             delegateToAgent executeDelegated approveHumanOnlyGate executePrivilegedHuman))))
  safety:
  '(and (not (. h scopeAmplified))
        (not (. h impersonatedHuman))
        (not (. h zombieDelegatedUse))
        (not (. h unverifiedPrivileged)))
  traces:
  '((checkSafe
      (action checkSafe ()
        (all (assert safety) (keep-h))))
    (checkUnsafe
      (action checkUnsafe ()
        (all (assert (not safety)) (keep-h))))
    (attenuatedDelegationAndStepUpSafeTest
      (run attenuatedDelegationAndStepUpSafeTest
        (then init (call delegateToAgentAs 1) executeDelegated
              performStepUp executePrivilegedHuman (call approveHumanOnlyGateAs #f)
              (all (assert (= (. h executedScopeLevel) 1))
                   (assert (= (. h humanGatesApproved) 1))
                   (assert safety)
                   (keep-h)))))
    (revocationBlocksDelegatedAgentTest
      (run revocationBlocksDelegatedAgentTest
        (then init (call delegateToAgentAs 2) revokeHumanSession executeDelegated
              (all (assert (= (. h executedScopeLevel) 0))
                   (assert safety)
                   (keep-h)))))
    (scopeAmplificationCountermodelTest
      (run scopeAmplificationCountermodelTest
        (then init (call delegateToAgentNoAtten 3) checkUnsafe)))
    (actorImpersonationCountermodelTest
      (run actorImpersonationCountermodelTest
        (then init (call delegateToAgentAs 1) (call approveGateNoProvenance #t) checkUnsafe)))
    (zombieDelegatedCountermodelTest
      (run zombieDelegatedCountermodelTest
        (then init (call delegateToAgentAs 2) revokeHumanSession executeDelegatedNoRevoke checkUnsafe)))
    (stepUpBypassCountermodelTest
      (run stepUpBypassCountermodelTest
        (then init executePrivilegedNoStepUp checkUnsafe))))
  countermodels:
  (list OboScopeAmplificationCountermodel
        OboActorImpersonationCountermodel
        OboZombieRevokedDelegationCountermodel
        UnverifiedStepUpBypassCountermodel)
  limits: "Finite RFC 8693 OBO delegation and RFC 9470 step-up abstraction; does not model JWT signature verification, multi-hop nested act arrays beyond depth 1, or IdP MFA phishing resistance.")

(.def (OboScopeAmplificationCountermodel @ DelegatedAgentAuthzModel)
  identity: 'threat.identity.delegated-agent-authz.scope-amplification
  dropped-guard: 'obo-scope-attenuation
  step-action: "stepScopeAmplification"
  derive-from-transition: 'delegateToAgentAs
  derive-action-name: 'delegateToAgentNoAtten
  derive-step-call: '(nondet ((reqScope (set 1 2 3)))
                       (call delegateToAgentNoAtten reqScope))
  expected-itf-predicate: "h.scopeAmplified == true")

(.def (OboActorImpersonationCountermodel @ DelegatedAgentAuthzModel)
  identity: 'threat.identity.delegated-agent-authz.actor-impersonation
  dropped-guard: 'obo-actor-provenance
  step-action: "stepActorImpersonation"
  derive-from-transition: 'approveHumanOnlyGateAs
  derive-action-name: 'approveGateNoProvenance
  derive-step-call: '(nondet ((isAgent (set #f #t)))
                       (call approveGateNoProvenance isAgent))
  expected-itf-predicate: "h.impersonatedHuman == true")

(.def (OboZombieRevokedDelegationCountermodel @ DelegatedAgentAuthzModel)
  identity: 'threat.identity.delegated-agent-authz.zombie-revoked-delegation
  dropped-guard: 'obo-revocation-currency
  step-action: "stepZombieDelegation"
  derive-from-transition: 'executeDelegated
  derive-action-name: 'executeDelegatedNoRevoke
  expected-itf-predicate: "h.zombieDelegatedUse == true")

(.def (UnverifiedStepUpBypassCountermodel @ DelegatedAgentAuthzModel)
  identity: 'threat.identity.delegated-agent-authz.step-up-bypass
  dropped-guard: 'step-up-verified-floor
  step-action: "stepStepUpBypass"
  derive-from-transition: 'executePrivilegedHuman
  derive-action-name: 'executePrivilegedNoStepUp
  expected-itf-predicate: "h.unverifiedPrivileged == true")
