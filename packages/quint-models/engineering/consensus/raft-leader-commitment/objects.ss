;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Raft Consensus Leader Election & Figure 8 Current-Term Commitment model.
;;; Co-located Yuanxu unit: single source of truth alongside RaftLeaderCommitment.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export RaftLeaderCommitmentModel)

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
  limits: "Finite 3-node single-slot Raft election and Figure 8 commitment abstraction; does not model multi-index prefix matching, log compaction snapshots, or dynamic membership joint consensus.")
