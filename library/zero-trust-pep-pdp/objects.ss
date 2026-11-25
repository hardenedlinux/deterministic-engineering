;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Zero Trust PEP/PDP separation model under concurrent policy updates and revocation.
(import :clan/poo/object
        (only-in "../authority-currentness/objects.ss" AuthorityCurrentnessModel))
(export ZeroTrustPepPdpModel StalePolicyDecisionCountermodel)

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
  invariant: "PEP enforces an effect only when the PDP decision matches the current policy epoch and active subject standing."
  parameters: '()
  state: '((policyEpoch "int" "0")
           (policyAllowed "bool" "true")
           (revoked "bool" "false")
           (decided "bool" "false")
           (decidedEpoch "int" "0")
           (decidedAllowed "bool" "false")
           (executed "int" "0")
           (unsafe "bool" "false"))
  guards: '((policy-epoch-currency "epochCurrent(h.policyEpoch, h.decidedEpoch)")
            (policy-active "h.policyAllowed and not(h.revoked)"))
  transitions:
  '((pdpEvaluate "action pdpEvaluate = if (not(h.decided))\n    h' = h.with(\"decided\", true).with(\"decidedEpoch\", h.policyEpoch).with(\"decidedAllowed\", h.policyAllowed and not(h.revoked))\n    else h' = h")
    (policyDeny "action policyDeny = if (h.policyEpoch < 3)\n    h' = h.with(\"policyAllowed\", false).with(\"policyEpoch\", h.policyEpoch + 1) else h' = h")
    (policyAllow "action policyAllow = if (h.policyEpoch < 3)\n    h' = h.with(\"policyAllowed\", true).with(\"policyEpoch\", h.policyEpoch + 1) else h' = h")
    (revokeSubject "action revokeSubject = if (not(h.revoked) and h.policyEpoch < 3)\n    h' = h.with(\"revoked\", true).with(\"policyEpoch\", h.policyEpoch + 1) else h' = h")
    (pepEnforce "action pepEnforce = if (h.decided and h.decidedAllowed and epochCurrent(h.policyEpoch, h.decidedEpoch) and h.policyAllowed and not(h.revoked))\n    h' = h.with(\"decided\", false).with(\"executed\", h.executed + 1)\n      .with(\"unsafe\", h.unsafe or not(h.policyAllowed) or h.revoked or not(epochCurrent(h.policyEpoch, h.decidedEpoch)))\n    else h' = h")
    (step "action step = any { pdpEvaluate, policyDeny, policyAllow, revokeSubject, pepEnforce }"))
  safety: "not(h.unsafe)"
  traces:
  '((checkSafe "action checkSafe = all { assert(safety), h' = h }")
    (checkBlocked "action checkBlocked = all { assert(h.executed == 0), assert(safety), h' = h }")
    (checkUnsafe "action checkUnsafe = all { assert(not(safety)), h' = h }")
    (validEnforceTest "run validEnforceTest = init.then(pdpEvaluate).then(pepEnforce).then(all { assert(h.executed == 1), assert(safety), h' = h })")
    (policyDenyBlocksEnforceTest "run policyDenyBlocksEnforceTest = init.then(pdpEvaluate).then(policyDeny).then(pepEnforce).then(checkBlocked)")
    (revocationBlocksEnforceTest "run revocationBlocksEnforceTest = init.then(pdpEvaluate).then(revokeSubject).then(pepEnforce).then(checkBlocked)")
    (staleDecisionCountermodelTest "run staleDecisionCountermodelTest = init.then(pdpEvaluate).then(policyDeny).then(pepEnforceStale).then(checkUnsafe)"))
  countermodels: (list StalePolicyDecisionCountermodel)
  limits: "Finite PEP/PDP policy-epoch abstraction; does not model transport cryptography, clock skew, or policy language semantics.")

;; Weakened descendant: PEP trusts cached PDP decision without re-checking policy epoch or revocation.
(.def (StalePolicyDecisionCountermodel @ ZeroTrustPepPdpModel)
  identity: 'threat.zero-trust-pep-pdp.stale-policy-decision
  dropped-guard: 'policy-epoch-currency
  step-action: "stepStalePolicy"
  counter-action: "action pepEnforceStale = if (h.decided and h.decidedAllowed)\n    h' = h.with(\"decided\", false).with(\"executed\", h.executed + 1)\n      .with(\"unsafe\", h.unsafe or not(h.policyAllowed) or h.revoked or not(epochCurrent(h.policyEpoch, h.decidedEpoch)))\n    else h' = h\n  action stepStalePolicy = any { step, pepEnforceStale }"
  expected-itf-predicate: "h.unsafe == true and h.executed >= 1")
