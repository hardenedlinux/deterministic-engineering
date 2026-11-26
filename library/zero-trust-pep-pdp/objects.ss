;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Zero Trust PEP/PDP separation model under concurrent policy updates and revocation.
;;; Emergent safety without synthetic unsafe flags; countermodels auto-derived via (guard ...).
(import :clan/poo/object
        (only-in "../authority-currentness/objects.ss" AuthorityCurrentnessModel))
(export ZeroTrustPepPdpModel
        StalePolicyDecisionCountermodel
        RevokedPolicyBypassCountermodel)

(.def (ZeroTrustPepPdpModel @ AuthorityCurrentnessModel)
  identity: 'threat.zero-trust-pep-pdp
  family: 'threat.zero-trust-pep-pdp
  quint-module: "zero_trust_pep_pdp"
  quint-file: "ZeroTrustPepPdp.qnt"
  domain-dir: "threat/zero-trust-pep-pdp"
  quint-imports: '(("authority_currentness" "../authority-currentness/AuthorityCurrentness"))
  rules: '((zt-pep-pdp-current ZT-PEP-CUR quint)
           (zt-pep-pdp-stale ZT-PEP-STALE quint))
  dependencies: '((ZT-PEP-CUR source) (ZT-PEP-CUR profile) (ZT-PEP-CUR method)
                  (ZT-PEP-STALE source) (ZT-PEP-STALE profile) (ZT-PEP-STALE method))
  invariant: "PEP enforces an effect only when the PDP decision matches the current policy epoch and active non-revoked subject standing."
  parameters: '()
  state: '((policyEpoch "int" "0")
           (policyAllowed "bool" "true")
           (revoked "bool" "false")
           (decided "bool" "false")
           (decidedEpoch "int" "0")
           (decidedAllowed "bool" "false")
           (executed "int" "0")
           (lastEnforcedEpoch "int" "0")
           (lastEnforcedPolicyEpoch "int" "0")
           (lastEnforcedAllowed "bool" "true")
           (lastEnforcedRevoked "bool" "false"))
  guards: '((policy-epoch-currency (call epochCurrent (. h policyEpoch) (. h decidedEpoch)))
            (policy-active (and (. h policyAllowed) (not (. h revoked)))))
  transitions:
  '((pdpEvaluate
     (action pdpEvaluate ()
       (if (not (. h decided))
         (set-h (decided #t)
                (decidedEpoch (. h policyEpoch))
                (decidedAllowed (and (. h policyAllowed) (not (. h revoked)))))
         (keep-h))))
    (policyDeny
     (action policyDeny ()
       (if (< (. h policyEpoch) 3)
         (set-h (policyAllowed #f) (policyEpoch (+ (. h policyEpoch) 1)))
         (keep-h))))
    (policyAllow
     (action policyAllow ()
       (if (< (. h policyEpoch) 3)
         (set-h (policyAllowed #t) (policyEpoch (+ (. h policyEpoch) 1)))
         (keep-h))))
    (revokeSubject
     (action revokeSubject ()
       (if (not (. h revoked))
         (set-h (revoked #t))
         (keep-h))))
    (pepEnforce
     (action pepEnforce ()
       (if (and (. h decided)
                (. h decidedAllowed)
                (guard policy-epoch-currency (call epochCurrent (. h policyEpoch) (. h decidedEpoch)))
                (guard policy-active (and (. h policyAllowed) (not (. h revoked)))))
         (set-h (decided #f)
                (executed (+ (. h executed) 1))
                (lastEnforcedEpoch (. h decidedEpoch))
                (lastEnforcedPolicyEpoch (. h policyEpoch))
                (lastEnforcedAllowed (. h policyAllowed))
                (lastEnforcedRevoked (. h revoked)))
         (keep-h))))
    (step
     (action step () (any pdpEvaluate policyDeny policyAllow revokeSubject pepEnforce))))
  safety:
  '(or (= (. h executed) 0)
       (and (= (. h lastEnforcedEpoch) (. h lastEnforcedPolicyEpoch))
            (. h lastEnforcedAllowed)
            (not (. h lastEnforcedRevoked))))
  traces:
  '((checkSafe (action checkSafe () (all (assert safety) (keep-h))))
    (checkBlocked (action checkBlocked () (all (assert (= (. h executed) 0)) (assert safety) (keep-h))))
    (checkUnsafe (action checkUnsafe () (all (assert (not safety)) (keep-h))))
    (validEnforceTest
     (run validEnforceTest
       (then init pdpEvaluate pepEnforce
             (all (assert (= (. h executed) 1)) (assert safety) (keep-h)))))
    (policyDenyBlocksEnforceTest
     (run policyDenyBlocksEnforceTest
       (then init pdpEvaluate policyDeny pepEnforce checkBlocked)))
    (revocationBlocksEnforceTest
     (run revocationBlocksEnforceTest
       (then init pdpEvaluate revokeSubject pepEnforce checkBlocked)))
    (staleDecisionCountermodelTest
     (run staleDecisionCountermodelTest
       (then init pdpEvaluate policyAllow pepEnforceStale checkUnsafe)))
    (revokedSubjectCountermodelTest
     (run revokedSubjectCountermodelTest
       (then init pdpEvaluate revokeSubject pepEnforceIgnoreRevocation checkUnsafe))))
  countermodels: (list StalePolicyDecisionCountermodel RevokedPolicyBypassCountermodel)
  limits: "Finite PEP/PDP policy-epoch abstraction; does not model transport cryptography, clock skew, or policy language semantics.")

;; Weakened descendant 1: PEP trusts cached PDP decision across policy epoch rollovers.
(.def (StalePolicyDecisionCountermodel @ ZeroTrustPepPdpModel)
  identity: 'threat.zero-trust-pep-pdp.stale-policy-decision
  dropped-guard: 'policy-epoch-currency
  step-action: "stepStalePolicy"
  derive-from-transition: 'pepEnforce
  derive-action-name: 'pepEnforceStale
  expected-itf-predicate: "h.executed >= 1 and h.lastEnforcedEpoch != h.lastEnforcedPolicyEpoch")

;; Weakened descendant 2: PEP ignores immediate revocation within the same policy epoch.
(.def (RevokedPolicyBypassCountermodel @ ZeroTrustPepPdpModel)
  identity: 'threat.zero-trust-pep-pdp.revoked-policy-bypass
  dropped-guard: 'policy-active
  step-action: "stepIgnoreRevocation"
  derive-from-transition: 'pepEnforce
  derive-action-name: 'pepEnforceIgnoreRevocation
  expected-itf-predicate: "h.executed >= 1 and h.lastEnforcedRevoked == true")
