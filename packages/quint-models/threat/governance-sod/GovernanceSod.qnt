// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// Projected from Scheme POO module threat.governance-sod. Do not edit by hand.
// Limits: Finite two-principal governance abstraction; does not model cryptographic identity attestation or multi-quorum threshold committees.
module governance_sod {
  import authority_currentness.* from "../authority-currentness/AuthorityCurrentness"
  type State = { proposer: int, approver: int, vetoed: bool, executed: bool, unsafe: bool }
  var h: State
  action init = h' = { proposer: 0, approver: 0, vetoed: false, executed: false, unsafe: false }
  action proposeAs(actor: int): bool = if (h.proposer == 0 and actor > 0)
    h' = h.with("proposer", actor)
    else h' = h
  action propose = { nondet actor = Set(1, 2).oneOf()
    proposeAs(actor) }
  action approveAs(actor: int): bool = if (h.proposer > 0 and h.approver == 0 and actor != h.proposer and not(h.vetoed))
    h' = h.with("approver", actor)
    else h' = h
  action approve = { nondet actor = Set(1, 2).oneOf()
    approveAs(actor) }
  action veto = if (not(h.executed))
    h' = h.with("vetoed", true)
    else h' = h
  action execute = if (h.proposer > 0 and h.approver > 0 and h.approver != h.proposer and not(h.vetoed) and not(h.executed))
    h' = h.with("executed", true)
    else h' = h
  action step = any { propose, approve, veto, execute }
  val safety = not(h.unsafe) and (not(h.executed) or (h.proposer > 0 and h.approver > 0 and h.approver != h.proposer and not(h.vetoed)))
  // Countermodel threat.governance-sod.self-approval (dropped guard: sod-distinct-actor)
  action selfApproveAndExec = if (h.proposer > 0 and not(h.executed))
    h' = h.with("approver", h.proposer).with("executed", true).with("unsafe", true)
    else h' = h
  action stepSelfApproval = any { step, selfApproveAndExec }
  // Countermodel threat.governance-sod.veto-override (dropped guard: veto-precedence)
  action executeOverVeto = if (h.proposer > 0 and h.approver > 0 and h.vetoed and not(h.executed))
    h' = h.with("executed", true).with("unsafe", true)
    else h' = h
  action stepVetoOverride = any { step, executeOverVeto }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run validDualControlTest = init.then(proposeAs(1)).then(approveAs(2)).then(execute).then(all { assert(h.executed), assert(safety), h' = h })
  run selfApprovalBlockedTest = init.then(proposeAs(1)).then(approveAs(1)).then(execute).then(all { assert(not(h.executed)), assert(safety), h' = h })
  run vetoBlocksExecutionTest = init.then(proposeAs(1)).then(approveAs(2)).then(veto).then(execute).then(all { assert(not(h.executed)), assert(safety), h' = h })
  run selfApprovalCountermodelTest = init.then(proposeAs(1)).then(selfApproveAndExec).then(checkUnsafe)
}
