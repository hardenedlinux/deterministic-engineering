// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.zero-trust-pep-pdp
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel policy-epoch-currency step=stepStalePolicy max-steps=6 itf="h.executed >= 1 and h.lastEnforcedEpoch != h.lastEnforcedPolicyEpoch"
// @countermodel policy-active step=stepIgnoreRevocation max-steps=6 itf="h.executed >= 1 and h.lastEnforcedRevoked == true"
// Limits: Finite PEP/PDP policy-epoch abstraction; does not model transport cryptography, clock skew, or policy language semantics.
module zero_trust_pep_pdp {
  import authority_currentness.* from "../authority-currentness/AuthorityCurrentness"
  type State = { policyEpoch: int, policyAllowed: bool, revoked: bool, decided: bool, decidedEpoch: int, decidedAllowed: bool, executed: int, lastEnforcedEpoch: int, lastEnforcedPolicyEpoch: int, lastEnforcedAllowed: bool, lastEnforcedRevoked: bool }
  var h: State
  action init = h' = { policyEpoch: 0, policyAllowed: true, revoked: false, decided: false, decidedEpoch: 0, decidedAllowed: false, executed: 0, lastEnforcedEpoch: 0, lastEnforcedPolicyEpoch: 0, lastEnforcedAllowed: true, lastEnforcedRevoked: false }
  action pdpEvaluate = if (not(h.decided)) h' = h.with("decided", true).with("decidedEpoch", h.policyEpoch).with("decidedAllowed", (h.policyAllowed and not(h.revoked))) else h' = h
  action policyDeny = if (h.policyEpoch < 3) h' = h.with("policyAllowed", false).with("policyEpoch", (h.policyEpoch + 1)) else h' = h
  action policyAllow = if (h.policyEpoch < 3) h' = h.with("policyAllowed", true).with("policyEpoch", (h.policyEpoch + 1)) else h' = h
  action revokeSubject = if (not(h.revoked)) h' = h.with("revoked", true) else h' = h
  action pepEnforce = if ((h.decided and h.decidedAllowed and epochCurrent(h.policyEpoch, h.decidedEpoch) and (h.policyAllowed and not(h.revoked)))) h' = h.with("decided", false).with("executed", (h.executed + 1)).with("lastEnforcedEpoch", h.decidedEpoch).with("lastEnforcedPolicyEpoch", h.policyEpoch).with("lastEnforcedAllowed", h.policyAllowed).with("lastEnforcedRevoked", h.revoked) else h' = h
  action step = any { pdpEvaluate, policyDeny, policyAllow, revokeSubject, pepEnforce }
  val safety = (h.executed == 0 or (h.lastEnforcedEpoch == h.lastEnforcedPolicyEpoch and h.lastEnforcedAllowed and not(h.lastEnforcedRevoked)))
  // Countermodel threat.zero-trust-pep-pdp.stale-policy-decision (dropped guard: policy-epoch-currency)
  action pepEnforceStale = if ((h.decided and h.decidedAllowed and true and (h.policyAllowed and not(h.revoked)))) h' = h.with("decided", false).with("executed", (h.executed + 1)).with("lastEnforcedEpoch", h.decidedEpoch).with("lastEnforcedPolicyEpoch", h.policyEpoch).with("lastEnforcedAllowed", h.policyAllowed).with("lastEnforcedRevoked", h.revoked) else h' = h
  action stepStalePolicy = any { step, pepEnforceStale }
  // Countermodel threat.zero-trust-pep-pdp.revoked-policy-bypass (dropped guard: policy-active)
  action pepEnforceIgnoreRevocation = if ((h.decided and h.decidedAllowed and epochCurrent(h.policyEpoch, h.decidedEpoch) and true)) h' = h.with("decided", false).with("executed", (h.executed + 1)).with("lastEnforcedEpoch", h.decidedEpoch).with("lastEnforcedPolicyEpoch", h.policyEpoch).with("lastEnforcedAllowed", h.policyAllowed).with("lastEnforcedRevoked", h.revoked) else h' = h
  action stepIgnoreRevocation = any { step, pepEnforceIgnoreRevocation }
  action checkSafe = all { assert(safety), h' = h }
  action checkBlocked = all { assert(h.executed == 0), assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run validEnforceTest = init.then(pdpEvaluate).then(pepEnforce).then(all { assert(h.executed == 1), assert(safety), h' = h })
  run policyDenyBlocksEnforceTest = init.then(pdpEvaluate).then(policyDeny).then(pepEnforce).then(checkBlocked)
  run revocationBlocksEnforceTest = init.then(pdpEvaluate).then(revokeSubject).then(pepEnforce).then(checkBlocked)
  run staleDecisionCountermodelTest = init.then(pdpEvaluate).then(policyAllow).then(pepEnforceStale).then(checkUnsafe)
  run revokedSubjectCountermodelTest = init.then(pdpEvaluate).then(revokeSubject).then(pepEnforceIgnoreRevocation).then(checkUnsafe)
}
