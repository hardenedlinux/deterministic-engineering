;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Byzantine Fault Tolerant (BFT) Consensus Quorum Intersection & Locked-Block View-Change Safety.
;;; Co-located Yuanxu unit: single source of truth alongside BftQuorumLock.qnt and README.org.
;;; Models n = 3f + 1 (n=4, f=1): 3 honest replicas + 1 Byzantine equivocator who freely votes
;;; for both conflicting values in every round. Verifies agreement under 2f+1 quorum intersection,
;;; precommit lock recording, and view-change lock respect.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export BftQuorumLockModel
        BftSubQuorumCommitCountermodel
        BftIgnoreLockCountermodel
        BftMissingLockOnPreCommitCountermodel
        BftStaleViewPreCommitCountermodel)

(.def (BftQuorumLockModel @ ThreatModel.)
  identity: 'engineering.consensus.bft-quorum-lock
  family: 'engineering.consensus.bft-quorum-lock
  title: "BFT Quorum Intersection & Locked-Block View-Change Safety (PBFT / Tendermint / HotStuff)"
  subdomain: 'quint.engineering.consensus
  papers:
  '(("M. Castro & B. Liskov (USENIX OSDI 1999)"
     "Practical Byzantine Fault Tolerance (PBFT): 2f+1 quorum intersection under f Byzantine replicas.")
    ("E. Buchman, J. Kwon & Z. Milosevic (2018)"
     "The latest gossip on BFT consensus (Tendermint / CometBFT): polka locks and view-change safety.")
    ("M. Yin, D. Malkhi, M. K. Reiter, G. G. Gueta & I. Abraham (ACM PODC 2019)"
     "HotStuff: BFT Consensus with Linearity and Responsiveness — lockedQC safety across views."))
  quint-module: "consensus_bft_quorum_lock"
  quint-file: "BftQuorumLock.qnt"
  domain-dir: "engineering/consensus/bft-quorum-lock"
  quint-imports: '()
  verify-depth: 10
  countermodel-depth: 9
  rules:
  '((bft-quorum-threshold CONS-BFT-QUORUM quint)
    (bft-lock-respect CONS-BFT-LOCK-RESPECT quint)
    (bft-commit-requires-lock CONS-BFT-LOCK-RECORD quint)
    (bft-monotonic-view CONS-BFT-MONO-VIEW quint))
  dependencies:
  '((CONS-BFT-QUORUM source)
    (CONS-BFT-QUORUM profile)
    (CONS-BFT-QUORUM method)
    (CONS-BFT-LOCK-RESPECT source)
    (CONS-BFT-LOCK-RESPECT profile)
    (CONS-BFT-LOCK-RESPECT method)
    (CONS-BFT-LOCK-RECORD source)
    (CONS-BFT-LOCK-RECORD profile)
    (CONS-BFT-LOCK-RECORD method)
    (CONS-BFT-MONO-VIEW source)
    (CONS-BFT-MONO-VIEW profile)
    (CONS-BFT-MONO-VIEW method))
  invariant: "Byzantine Agreement: despite an equivocating Byzantine replica voting for both conflicting values in every round, two distinct values are never both committed across view changes."
  parameters: '()
  state:
  '((r1Prep1 "int" "0")
    (r1Prep2 "int" "0")
    (r1Prep3 "int" "0")
    (r1Pc1 "int" "0")
    (r1Pc2 "int" "0")
    (r1Pc3 "int" "0")
    (lock1 "int" "0")
    (lock2 "int" "0")
    (lock3 "int" "0")
    (r2Prep1 "int" "0")
    (r2Prep2 "int" "0")
    (r2Prep3 "int" "0")
    (committed1 "bool" "false")
    (committed2 "bool" "false"))
  guards:
  '((bft-quorum-threshold (>= (+ votes 1) 3))
    (bft-lock-respect (or (= nodeLock 0) (= nodeLock v)))
    (bft-commit-requires-lock (= recordedLock v))
    (bft-monotonic-view (= nodeR2Prep 0)))
  transitions:
  '((r1PrepCount1
      (val r1PrepCount1
        (+ (+ (if (= (. h r1Prep1) 1) 1 0)
              (if (= (. h r1Prep2) 1) 1 0))
           (if (= (. h r1Prep3) 1) 1 0))))
    (r1PrepCount2
      (val r1PrepCount2
        (+ (+ (if (= (. h r1Prep1) 2) 1 0)
              (if (= (. h r1Prep2) 2) 1 0))
           (if (= (. h r1Prep3) 2) 1 0))))
    (r1PcCount1
      (val r1PcCount1
        (+ (+ (if (= (. h r1Pc1) 1) 1 0)
              (if (= (. h r1Pc2) 1) 1 0))
           (if (= (. h r1Pc3) 1) 1 0))))
    (r1PcCount2
      (val r1PcCount2
        (+ (+ (if (= (. h r1Pc1) 2) 1 0)
              (if (= (. h r1Pc2) 2) 1 0))
           (if (= (. h r1Pc3) 2) 1 0))))
    (r2PrepCount1
      (val r2PrepCount1
        (+ (+ (if (= (. h r2Prep1) 1) 1 0)
              (if (= (. h r2Prep2) 1) 1 0))
           (if (= (. h r2Prep3) 1) 1 0))))
    (r2PrepCount2
      (val r2PrepCount2
        (+ (+ (if (= (. h r2Prep1) 2) 1 0)
              (if (= (. h r2Prep2) 2) 1 0))
           (if (= (. h r2Prep3) 2) 1 0))))
    (r1PrepareAs
      (action r1PrepareAs ((node "int") (v "int")) "bool"
        (if (and (or (= v 1) (= v 2))
                 (= (if (= node 1) (. h r1Prep1) (if (= node 2) (. h r1Prep2) (. h r1Prep3))) 0))
          (if (= node 1)
            (set-h (r1Prep1 v))
            (if (= node 2)
              (set-h (r1Prep2 v))
              (set-h (r1Prep3 v))))
          (keep-h))))
    (r1Prepare
      (action r1Prepare ()
        (nondet ((node (set 1 2 3))
                 (v (set 1 2)))
          (call r1PrepareAs node v))))
    (r1PreCommitAs
      (action r1PreCommitAs ((node "int") (v "int")) "bool"
        (if (and (or (= v 1) (= v 2))
                 (= (if (= node 1) (. h r1Pc1) (if (= node 2) (. h r1Pc2) (. h r1Pc3))) 0)
                 (guard bft-monotonic-view
                        (= (if (= node 1) (. h r2Prep1) (if (= node 2) (. h r2Prep2) (. h r2Prep3))) 0))
                 (>= (+ (if (= v 1) r1PrepCount1 r1PrepCount2) 1) 3))
          (if (= node 1)
            (set-h (r1Pc1 v) (lock1 (guard bft-commit-requires-lock v 0)))
            (if (= node 2)
              (set-h (r1Pc2 v) (lock2 (guard bft-commit-requires-lock v 0)))
              (set-h (r1Pc3 v) (lock3 (guard bft-commit-requires-lock v 0)))))
          (keep-h))))
    (r1PreCommit
      (action r1PreCommit ()
        (nondet ((node (set 1 2 3))
                 (v (set 1 2)))
          (call r1PreCommitAs node v))))
    (r1CommitAs
      (action r1CommitAs ((v "int")) "bool"
        (if (and (or (= v 1) (= v 2))
                 (>= (+ (if (= v 1) r1PcCount1 r1PcCount2) 1) 3))
          (if (= v 1)
            (set-h (committed1 #t))
            (set-h (committed2 #t)))
          (keep-h))))
    (r1Commit
      (action r1Commit ()
        (nondet ((v (set 1 2)))
          (call r1CommitAs v))))
    (r2PrepareAs
      (action r2PrepareAs ((node "int") (v "int")) "bool"
        (if (and (or (= v 1) (= v 2))
                 (= (if (= node 1) (. h r2Prep1) (if (= node 2) (. h r2Prep2) (. h r2Prep3))) 0)
                 (guard bft-lock-respect
                        (or (= (if (= node 1) (. h lock1) (if (= node 2) (. h lock2) (. h lock3))) 0)
                            (= (if (= node 1) (. h lock1) (if (= node 2) (. h lock2) (. h lock3))) v))))
          (if (= node 1)
            (set-h (r2Prep1 v))
            (if (= node 2)
              (set-h (r2Prep2 v))
              (set-h (r2Prep3 v))))
          (keep-h))))
    (r2Prepare
      (action r2Prepare ()
        (nondet ((node (set 1 2 3))
                 (v (set 1 2)))
          (call r2PrepareAs node v))))
    (r2CommitAs
      (action r2CommitAs ((v "int")) "bool"
        (if (and (or (= v 1) (= v 2))
                 (guard bft-quorum-threshold
                        (>= (+ (if (= v 1) r2PrepCount1 r2PrepCount2) 1) 3)
                        (>= (+ (if (= v 1) r2PrepCount1 r2PrepCount2) 1) 2)))
          (if (= v 1)
            (set-h (committed1 #t))
            (set-h (committed2 #t)))
          (keep-h))))
    (r2Commit
      (action r2Commit ()
        (nondet ((v (set 1 2)))
          (call r2CommitAs v))))
    (step
      (action step ()
        (any r1Prepare r1PreCommit r1Commit r2Prepare r2Commit))))
  safety: '(not (and (. h committed1) (. h committed2)))
  traces:
  '((checkSafe
      (action checkSafe ()
        (all (assert safety) (keep-h))))
    (checkUnsafe
      (action checkUnsafe ()
        (all (assert (not safety)) (keep-h))))
    (lockedBlockSurvivesViewChangeTest
      (run lockedBlockSurvivesViewChangeTest
        (then init
              (call r1PrepareAs 1 1)
              (call r1PrepareAs 2 1)
              (call r1PreCommitAs 1 1)
              (call r1PreCommitAs 2 1)
              (call r1CommitAs 1)
              (call r2PrepareAs 3 2)
              (call r2PrepareAs 2 2)
              (call r2CommitAs 2)
              (all (assert (. h committed1))
                   (assert (not (. h committed2)))
                   (assert safety)
                   (keep-h)))))
    (subQuorumForkCountermodelTest
      (run subQuorumForkCountermodelTest
        (then init
              (call r1PrepareAs 1 1)
              (call r1PrepareAs 2 1)
              (call r1PreCommitAs 1 1)
              (call r1PreCommitAs 2 1)
              (call r1CommitAs 1)
              (call r2PrepareAs 3 2)
              (call r2CommitSubQuorum 2)
              checkUnsafe)))
    (ignoreLockForkCountermodelTest
      (run ignoreLockForkCountermodelTest
        (then init
              (call r1PrepareAs 1 1)
              (call r1PrepareAs 2 1)
              (call r1PreCommitAs 1 1)
              (call r1PreCommitAs 2 1)
              (call r1CommitAs 1)
              (call r2PrepareAs 3 2)
              (call r2PrepareIgnoreLock 2 2)
              (call r2CommitAs 2)
              checkUnsafe)))
    (missingLockForkCountermodelTest
      (run missingLockForkCountermodelTest
        (then init
              (call r1PrepareAs 1 1)
              (call r1PrepareAs 2 1)
              (call r1PreCommitNoLock 1 1)
              (call r1PreCommitNoLock 2 1)
              (call r1CommitAs 1)
              (call r2PrepareAs 2 2)
              (call r2PrepareAs 3 2)
              (call r2CommitAs 2)
              checkUnsafe))))
  countermodels:
  (list BftSubQuorumCommitCountermodel
        BftIgnoreLockCountermodel
        BftMissingLockOnPreCommitCountermodel
        BftStaleViewPreCommitCountermodel)
  limits: "Finite 4-replica (3 honest + 1 equivocating Byzantine, n=3f+1) 2-view BFT quorum-intersection, view-monotonicity, and lock-respect abstraction; does not model partial-synchrony liveness, Pacemaker GST timeouts, or BLS threshold signature aggregation.")

(.def (BftSubQuorumCommitCountermodel @ BftQuorumLockModel)
  identity: 'engineering.consensus.bft-quorum-lock.sub-quorum-commit
  dropped-guard: 'bft-quorum-threshold
  step-action: "stepSubQuorumCommit"
  derive-from-transition: 'r2CommitAs
  derive-action-name: 'r2CommitSubQuorum
  derive-step-call: '(nondet ((v (set 1 2))) (call r2CommitSubQuorum v))
  expected-itf-predicate: "h.committed1 == true and h.committed2 == true")

(.def (BftIgnoreLockCountermodel @ BftQuorumLockModel)
  identity: 'engineering.consensus.bft-quorum-lock.ignore-lock
  dropped-guard: 'bft-lock-respect
  step-action: "stepIgnoreLock"
  derive-from-transition: 'r2PrepareAs
  derive-action-name: 'r2PrepareIgnoreLock
  derive-step-call: '(nondet ((node (set 1 2 3)) (v (set 1 2))) (call r2PrepareIgnoreLock node v))
  expected-itf-predicate: "h.committed1 == true and h.committed2 == true")

(.def (BftMissingLockOnPreCommitCountermodel @ BftQuorumLockModel)
  identity: 'engineering.consensus.bft-quorum-lock.missing-lock-on-precommit
  dropped-guard: 'bft-commit-requires-lock
  step-action: "stepMissingLockOnPreCommit"
  derive-from-transition: 'r1PreCommitAs
  derive-action-name: 'r1PreCommitNoLock
  derive-step-call: '(nondet ((node (set 1 2 3)) (v (set 1 2))) (call r1PreCommitNoLock node v))
  expected-itf-predicate: "h.committed1 == true and h.committed2 == true")

(.def (BftStaleViewPreCommitCountermodel @ BftQuorumLockModel)
  identity: 'engineering.consensus.bft-quorum-lock.stale-view-precommit
  dropped-guard: 'bft-monotonic-view
  step-action: "stepStaleViewPreCommit"
  derive-from-transition: 'r1PreCommitAs
  derive-action-name: 'r1PreCommitStaleView
  derive-step-call: '(nondet ((node (set 1 2 3)) (v (set 1 2))) (call r1PreCommitStaleView node v))
  expected-itf-predicate: "h.committed1 == true and h.committed2 == true")
