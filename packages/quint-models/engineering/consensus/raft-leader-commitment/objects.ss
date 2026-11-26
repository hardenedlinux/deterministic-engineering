;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Raft Consensus Leader Election & Figure 8 Current-Term Commitment model.
;;; Co-located Yuanxu unit: single source of truth alongside RaftLeaderCommitment.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export RaftLeaderCommitmentModel
        Figure8OldTermCommitCountermodel
        StaleLogElectionCountermodel)

(.def (RaftLeaderCommitmentModel @ ThreatModel.)
  identity: 'engineering.consensus.raft-leader-commitment
  family: 'engineering.consensus.raft-leader-commitment
  title: "Raft Leader Election & Figure 8 Current-Term Commitment"
  subdomain: 'quint.engineering.consensus
  papers:
  '(("D. Ongaro & J. Ousterhout (USENIX ATC 2014)"
     "In Search of an Understandable Consensus Algorithm (Raft): §5.4.1 Election Restriction and §5.4.2 Figure 8 Current-Term Commitment Rule.")
    ("H. Howard, D. Malkhi & A. Spiegelman (OPODIS 2016)"
     "Flexible Paxos: Quorum Intersection Revisited for consensus leader election and commitment safety."))
  quint-module: "consensus_raft_commitment"
  quint-file: "RaftLeaderCommitment.qnt"
  domain-dir: "engineering/consensus/raft-leader-commitment"
  quint-imports: '()
  verify-depth: 10
  countermodel-depth: 9
  rules:
  '((election-log-up-to-date CONS-RAFT-ELECT quint)
    (current-term-commit-rule CONS-RAFT-FIG8 quint))
  dependencies:
  '((CONS-RAFT-ELECT source)
    (CONS-RAFT-ELECT profile)
    (CONS-RAFT-ELECT method)
    (CONS-RAFT-FIG8 source)
    (CONS-RAFT-FIG8 profile)
    (CONS-RAFT-FIG8 method))
  invariant: "Leader Completeness: once a slot-1 entry is committed, every subsequent elected leader contains that exact committed value."
  parameters: '()
  state:
  '((currentTerm "int" "1")
    (leaderId "int" "0")
    (n1Term "int" "0")
    (n1Val "int" "0")
    (n2Term "int" "0")
    (n2Val "int" "0")
    (n3Term "int" "0")
    (n3Val "int" "0")
    (committed "bool" "false")
    (committedVal "int" "0"))
  guards:
  '((election-log-up-to-date (>= candTerm voterTerm))
    (current-term-commit-rule (= leaderLogTerm (. h currentTerm))))
  transitions:
  '((leaderLogTerm
      (val leaderLogTerm
        (if (= (. h leaderId) 1)
          (. h n1Term)
          (if (= (. h leaderId) 2)
            (. h n2Term)
            (if (= (. h leaderId) 3)
              (. h n3Term)
              0)))))
    (leaderLogVal
      (val leaderLogVal
        (if (= (. h leaderId) 1)
          (. h n1Val)
          (if (= (. h leaderId) 2)
            (. h n2Val)
            (if (= (. h leaderId) 3)
              (. h n3Val)
              0)))))
    (leaderMatchCount
      (val leaderMatchCount
        (+ (+ (if (and (> leaderLogTerm 0) (= (. h n1Term) leaderLogTerm)) 1 0)
              (if (and (> leaderLogTerm 0) (= (. h n2Term) leaderLogTerm)) 1 0))
           (if (and (> leaderLogTerm 0) (= (. h n3Term) leaderLogTerm)) 1 0))))
    (electLeaderAs
      (action electLeaderAs ((cand "int") (voter "int")) "bool"
        (if (and (< (. h currentTerm) 5)
                 (!= cand voter)
                 (!= cand (. h leaderId))
                 (guard election-log-up-to-date
                        (>= (if (= cand 1)
                              (. h n1Term)
                              (if (= cand 2) (. h n2Term) (. h n3Term)))
                            (if (= voter 1)
                              (. h n1Term)
                              (if (= voter 2) (. h n2Term) (. h n3Term))))))
          (set-h (currentTerm (+ (. h currentTerm) 1))
                 (leaderId cand))
          (keep-h))))
    (electLeader
      (action electLeader ()
        (nondet ((cand (set 1 2 3))
                 (voter (set 1 2 3)))
          (call electLeaderAs cand voter))))
    (leaderPropose
      (action leaderPropose ()
        (if (and (> (. h leaderId) 0) (= leaderLogTerm 0))
          (if (= (. h leaderId) 1)
            (set-h (n1Term (. h currentTerm)) (n1Val 1))
            (if (= (. h leaderId) 2)
              (set-h (n2Term (. h currentTerm)) (n2Val 2))
              (set-h (n3Term (. h currentTerm)) (n3Val 3))))
          (keep-h))))
    (leaderReplicateTo
      (action leaderReplicateTo ((target "int")) "bool"
        (if (and (> (. h leaderId) 0)
                 (> leaderLogTerm 0)
                 (!= target (. h leaderId))
                 (!= (if (= target 1)
                       (. h n1Term)
                       (if (= target 2) (. h n2Term) (. h n3Term)))
                     leaderLogTerm))
          (if (= target 1)
            (set-h (n1Term leaderLogTerm) (n1Val leaderLogVal))
            (if (= target 2)
              (set-h (n2Term leaderLogTerm) (n2Val leaderLogVal))
              (set-h (n3Term leaderLogTerm) (n3Val leaderLogVal))))
          (keep-h))))
    (leaderReplicate
      (action leaderReplicate ()
        (nondet ((target (set 1 2 3)))
          (call leaderReplicateTo target))))
    (leaderCommit
      (action leaderCommit ()
        (if (and (> (. h leaderId) 0)
                 (not (. h committed))
                 (>= leaderMatchCount 2)
                 (guard current-term-commit-rule (= leaderLogTerm (. h currentTerm))))
          (set-h (committed #t)
                 (committedVal leaderLogVal))
          (keep-h))))
    (step
      (action step ()
        (any electLeader leaderPropose leaderReplicate leaderCommit))))
  safety:
  '(or (not (. h committed))
       (= (. h leaderId) 0)
       (= leaderLogVal (. h committedVal)))
  traces:
  '((checkSafe
      (action checkSafe ()
        (all (assert safety) (keep-h))))
    (checkUnsafe
      (action checkUnsafe ()
        (all (assert (not safety)) (keep-h))))
    (validCurrentTermCommitTest
      (run validCurrentTermCommitTest
        (then init
              (call electLeaderAs 1 2)
              leaderPropose
              (call leaderReplicateTo 2)
              leaderCommit
              (call electLeaderAs 3 2)
              (all (assert (. h committed))
                   (assert (= (. h leaderId) 1))
                   (assert safety)
                   (keep-h)))))
    (figure8GuardBlocksOldTermCommitTest
      (run figure8GuardBlocksOldTermCommitTest
        (then init
              (call electLeaderAs 1 2)
              leaderPropose
              (call electLeaderAs 3 2)
              leaderPropose
              (call electLeaderAs 1 2)
              (call leaderReplicateTo 2)
              leaderCommit
              (all (assert (not (. h committed)))
                   (assert safety)
                   (keep-h)))))
    (figure8OverwriteCountermodelTest
      (run figure8OverwriteCountermodelTest
        (then init
              (call electLeaderAs 1 2)
              leaderPropose
              (call electLeaderAs 3 2)
              leaderPropose
              (call electLeaderAs 1 2)
              (call leaderReplicateTo 2)
              leaderCommitOldTerm
              (call electLeaderAs 3 2)
              checkUnsafe)))
    (staleElectionCountermodelTest
      (run staleElectionCountermodelTest
        (then init
              (call electLeaderAs 1 2)
              leaderPropose
              (call leaderReplicateTo 2)
              leaderCommit
              (call electLeaderNoLogCheck 3 2)
              checkUnsafe))))
  countermodels:
  (list Figure8OldTermCommitCountermodel
        StaleLogElectionCountermodel)
  limits: "Finite 3-node single-slot Raft election and Figure 8 commitment abstraction; does not model multi-index prefix matching, log compaction snapshots, or dynamic membership joint consensus.")

(.def (Figure8OldTermCommitCountermodel @ RaftLeaderCommitmentModel)
  identity: 'engineering.consensus.raft-leader-commitment.figure8-old-term-commit
  dropped-guard: 'current-term-commit-rule
  step-action: "stepFigure8Commit"
  derive-from-transition: 'leaderCommit
  derive-action-name: 'leaderCommitOldTerm
  expected-itf-predicate: "h.committed == true and h.leaderId > 0 and ((h.leaderId == 1 and h.n1Val != h.committedVal) or (h.leaderId == 2 and h.n2Val != h.committedVal) or (h.leaderId == 3 and h.n3Val != h.committedVal))")

(.def (StaleLogElectionCountermodel @ RaftLeaderCommitmentModel)
  identity: 'engineering.consensus.raft-leader-commitment.stale-log-election
  dropped-guard: 'election-log-up-to-date
  step-action: "stepStaleLogElection"
  derive-from-transition: 'electLeaderAs
  derive-action-name: 'electLeaderNoLogCheck
  derive-step-call: '(nondet ((cand (set 1 2 3))
                              (voter (set 1 2 3)))
                       (call electLeaderNoLogCheck cand voter))
  expected-itf-predicate: "h.committed == true and h.leaderId > 0 and ((h.leaderId == 1 and h.n1Val != h.committedVal) or (h.leaderId == 2 and h.n2Val != h.committedVal) or (h.leaderId == 3 and h.n3Val != h.committedVal))")
