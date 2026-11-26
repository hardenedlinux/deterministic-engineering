;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Governance Separation of Duties (SoD) and Veto precedence threat model.
;;; Emergent safety (zero synthetic unsafe flags); countermodels auto-derived via (guard ...).
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
           (executed "bool" "false"))
  guards: '((sod-distinct-actor (and (> (. h proposer) 0) (!= actor (. h proposer))))
            (veto-precedence (not (. h vetoed))))
  transitions:
  '((proposeAs
     (action proposeAs ((actor "int")) "bool"
       (if (and (= (. h proposer) 0) (> actor 0))
         (set-h (proposer actor))
         (keep-h))))
    (propose
     (action propose ()
       (nondet ((actor (set 1 2)))
         (call proposeAs actor))))
    (approveAs
     (action approveAs ((actor "int")) "bool"
       (if (and (> (. h proposer) 0)
                (= (. h approver) 0)
                (guard sod-distinct-actor (!= actor (. h proposer)))
                (not (. h vetoed)))
         (set-h (approver actor))
         (keep-h))))
    (approve
     (action approve ()
       (nondet ((actor (set 1 2)))
         (call approveAs actor))))
    (veto
     (action veto ()
       (if (not (. h executed))
         (set-h (vetoed #t))
         (keep-h))))
    (execute
     (action execute ()
       (if (and (> (. h proposer) 0)
                (> (. h approver) 0)
                (guard veto-precedence (not (. h vetoed)))
                (not (. h executed)))
         (set-h (executed #t))
         (keep-h))))
    (step
     (action step () (any propose approve veto execute))))
  safety:
  '(or (not (. h executed))
       (and (> (. h proposer) 0)
            (> (. h approver) 0)
            (!= (. h approver) (. h proposer))
            (not (. h vetoed))))
  traces:
  '((checkSafe (action checkSafe () (all (assert safety) (keep-h))))
    (checkUnsafe (action checkUnsafe () (all (assert (not safety)) (keep-h))))
    (validDualControlTest
     (run validDualControlTest
       (then init (call proposeAs 1) (call approveAs 2) execute
             (all (assert (. h executed)) (assert safety) (keep-h)))))
    (selfApprovalBlockedTest
     (run selfApprovalBlockedTest
       (then init (call proposeAs 1) (call approveAs 1) execute
             (all (assert (not (. h executed))) (assert safety) (keep-h)))))
    (vetoBlocksExecutionTest
     (run vetoBlocksExecutionTest
       (then init (call proposeAs 1) (call approveAs 2) veto execute
             (all (assert (not (. h executed))) (assert safety) (keep-h)))))
    (selfApprovalCountermodelTest
     (run selfApprovalCountermodelTest
       (then init (call proposeAs 1) (call approveSelfAllowed 1) execute checkUnsafe)))
    (vetoOverrideCountermodelTest
     (run vetoOverrideCountermodelTest
       (then init (call proposeAs 1) (call approveAs 2) veto executeOverVeto checkUnsafe))))
  countermodels: (list SelfApprovalCountermodel VetoOverrideCountermodel)
  limits: "Finite two-principal governance abstraction; does not model cryptographic identity attestation or multi-quorum threshold committees.")

(.def (SelfApprovalCountermodel @ GovernanceSodModel)
  identity: 'threat.governance-sod.self-approval
  dropped-guard: 'sod-distinct-actor
  step-action: "stepSelfApproval"
  derive-from-transition: 'approveAs
  derive-action-name: 'approveSelfAllowed
  derive-step-call: '(nondet ((actor (set 1 2))) (call approveSelfAllowed actor))
  expected-itf-predicate: "h.executed == true and h.approver == h.proposer")

(.def (VetoOverrideCountermodel @ GovernanceSodModel)
  identity: 'threat.governance-sod.veto-override
  dropped-guard: 'veto-precedence
  step-action: "stepVetoOverride"
  derive-from-transition: 'execute
  derive-action-name: 'executeOverVeto
  expected-itf-predicate: "h.executed == true and h.vetoed == true")
