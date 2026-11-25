;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Governance Separation of Duties (SoD) and Veto precedence threat model.
;;; Models host-owned prior-actor provenance, distinct approver enforcement,
;;; and fail-closed forbid-veto precedence over permit approvals.
(import :clan/poo/object
        (only-in "../authority-currentness/objects.ss" AuthorityCurrentnessModel))
(export GovernanceSodModel
        SelfApprovalCountermodel
        VetoOverrideCountermodel)

(.def (GovernanceSodModel @ AuthorityCurrentnessModel)
  identity: 'threat.governance-sod
  family: 'threat.governance-sod
  quint-module: "governance_sod"
  quint-file: "GovernanceSod.qnt"
  domain-dir: "threat/governance-sod"
  quint-imports: '(("authority_currentness" "../authority-currentness/AuthorityCurrentness"))
  rules: '((sod-distinct-actor GOV-SOD-ACTOR quint)
           (veto-precedence GOV-VETO-PREC quint))
  dependencies: '((GOV-SOD-ACTOR source) (GOV-SOD-ACTOR profile) (GOV-SOD-ACTOR method)
                  (GOV-VETO-PREC source) (GOV-VETO-PREC profile) (GOV-VETO-PREC method))
  invariant: "An action executes only with a distinct approver (approver != proposer) and zero active forbid vetoes."
  parameters: '()
  state: '((proposer "int" "0")
           (approver "int" "0")
           (vetoed "bool" "false")
           (executed "bool" "false")
           (unsafe "bool" "false"))
  guards: '((sod-distinct-actor "h.proposer > 0 and actor != h.proposer")
            (veto-precedence "not(h.vetoed)"))
  transitions:
  '((proposeAs "action proposeAs(actor: int): bool = if (h.proposer == 0 and actor > 0)\n    h' = h.with(\"proposer\", actor)\n    else h' = h")
    (propose "action propose = { nondet actor = Set(1, 2).oneOf()\n    proposeAs(actor) }")
    (approveAs "action approveAs(actor: int): bool = if (h.proposer > 0 and h.approver == 0 and actor != h.proposer and not(h.vetoed))\n    h' = h.with(\"approver\", actor)\n    else h' = h")
    (approve "action approve = { nondet actor = Set(1, 2).oneOf()\n    approveAs(actor) }")
    (veto "action veto = if (not(h.executed))\n    h' = h.with(\"vetoed\", true)\n    else h' = h")
    (execute "action execute = if (h.proposer > 0 and h.approver > 0 and h.approver != h.proposer and not(h.vetoed) and not(h.executed))\n    h' = h.with(\"executed\", true)\n    else h' = h")
    (step "action step = any { propose, approve, veto, execute }"))
  safety: "not(h.unsafe) and (not(h.executed) or (h.proposer > 0 and h.approver > 0 and h.approver != h.proposer and not(h.vetoed)))"
  traces:
  '((checkSafe "action checkSafe = all { assert(safety), h' = h }")
    (checkUnsafe "action checkUnsafe = all { assert(not(safety)), h' = h }")
    (validDualControlTest "run validDualControlTest = init.then(proposeAs(1)).then(approveAs(2)).then(execute).then(all { assert(h.executed), assert(safety), h' = h })")
    (selfApprovalBlockedTest "run selfApprovalBlockedTest = init.then(proposeAs(1)).then(approveAs(1)).then(execute).then(all { assert(not(h.executed)), assert(safety), h' = h })")
    (vetoBlocksExecutionTest "run vetoBlocksExecutionTest = init.then(proposeAs(1)).then(approveAs(2)).then(veto).then(execute).then(all { assert(not(h.executed)), assert(safety), h' = h })")
    (selfApprovalCountermodelTest "run selfApprovalCountermodelTest = init.then(proposeAs(1)).then(selfApproveAndExec).then(checkUnsafe)"))
  countermodels: (list SelfApprovalCountermodel VetoOverrideCountermodel)
  limits: "Finite two-principal governance abstraction; does not model cryptographic identity attestation or multi-quorum threshold committees.")

(.def (SelfApprovalCountermodel @ GovernanceSodModel)
  identity: 'threat.governance-sod.self-approval
  dropped-guard: 'sod-distinct-actor
  step-action: "stepSelfApproval"
  counter-action: "action selfApproveAndExec = if (h.proposer > 0 and not(h.executed))\n    h' = h.with(\"approver\", h.proposer).with(\"executed\", true).with(\"unsafe\", true)\n    else h' = h\n  action stepSelfApproval = any { step, selfApproveAndExec }"
  expected-itf-predicate: "h.executed == true and h.approver == h.proposer")

(.def (VetoOverrideCountermodel @ GovernanceSodModel)
  identity: 'threat.governance-sod.veto-override
  dropped-guard: 'veto-precedence
  step-action: "stepVetoOverride"
  counter-action: "action executeOverVeto = if (h.proposer > 0 and h.approver > 0 and h.vetoed and not(h.executed))\n    h' = h.with(\"executed\", true).with(\"unsafe\", true)\n    else h' = h\n  action stepVetoOverride = any { step, executeOverVeto }"
  expected-itf-predicate: "h.executed == true and h.vetoed == true")
