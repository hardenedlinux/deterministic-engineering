// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// Projected from Scheme POO module threat.zero-trust-pep-pdp. Do not edit by hand.
// Limits: Finite PEP/PDP policy-epoch abstraction; does not model transport cryptography, clock skew, or policy language semantics.
module zero_trust_pep_pdp {
  import authority_currentness.* from "../authority-currentness/AuthorityCurrentness"
  type State = { policyEpoch: int, policyAllowed: bool, revoked: bool, decided: bool, decidedEpoch: int, decidedAllowed: bool, executed: int, unsafe: bool }
  var h: State
  action init = h' = { policyEpoch: 0, policyAllowed: true, revoked: false, decided: false, decidedEpoch: 0, decidedAllowed: false, executed: 0, unsafe: false }
  action pdpEvaluate = if (not(h.decided))
    h' = h.with("decided", true).with("decidedEpoch", h.policyEpoch).with("decidedAllowed", h.policyAllowed and not(h.revoked))
    else h' = h
  action policyDeny = if (h.policyEpoch < 3)
    h' = h.with("policyAllowed", false).with("policyEpoch", h.policyEpoch + 1) else h' = h
  action policyAllow = if (h.policyEpoch < 3)
    h' = h.with("policyAllowed", true).with("policyEpoch", h.policyEpoch + 1) else h' = h
  action revokeSubject = if (not(h.revoked) and h.policyEpoch < 3)
    h' = h.with("revoked", true).with("policyEpoch", h.policyEpoch + 1) else h' = h
  action pepEnforce = if (h.decided and h.decidedAllowed and epochCurrent(h.policyEpoch, h.decidedEpoch) and h.policyAllowed and not(h.revoked))
    h' = h.with("decided", false).with("executed", h.executed + 1)
      .with("unsafe", h.unsafe or not(h.policyAllowed) or h.revoked or not(epochCurrent(h.policyEpoch, h.decidedEpoch)))
    else h' = h
  action step = any { pdpEvaluate, policyDeny, policyAllow, revokeSubject, pepEnforce }
  val safety = not(h.unsafe)
  // Countermodel threat.zero-trust-pep-pdp.stale-policy-decision (dropped guard: policy-epoch-currency)
  action pepEnforceStale = if (h.decided and h.decidedAllowed)
    h' = h.with("decided", false).with("executed", h.executed + 1)
      .with("unsafe", h.unsafe or not(h.policyAllowed) or h.revoked or not(epochCurrent(h.policyEpoch, h.decidedEpoch)))
    else h' = h
  action stepStalePolicy = any { step, pepEnforceStale }
  action checkSafe = all { assert(safety), h' = h }
  action checkBlocked = all { assert(h.executed == 0), assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run validEnforceTest = init.then(pdpEvaluate).then(pepEnforce).then(all { assert(h.executed == 1), assert(safety), h' = h })
  run policyDenyBlocksEnforceTest = init.then(pdpEvaluate).then(policyDeny).then(pepEnforce).then(checkBlocked)
  run revocationBlocksEnforceTest = init.then(pdpEvaluate).then(revokeSubject).then(pepEnforce).then(checkBlocked)
  run staleDecisionCountermodelTest = init.then(pdpEvaluate).then(policyDeny).then(pepEnforceStale).then(checkUnsafe)
}
