;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Byzantine Fault Tolerant (BFT) Consensus Quorum Intersection & Locked-Block View-Change Safety.
;;; Co-located Yuanxu unit: single source of truth alongside BftQuorumLock.qnt and README.org.
;;; Models n = 3f + 1 (n=4, f=1): 3 honest replicas + 1 Byzantine equivocator who freely votes
;;; for both conflicting values in every round. Verifies agreement under 2f+1 quorum intersection,
;;; precommit lock recording, and view-change lock respect.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export BftQuorumLockModel)

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
  limits: "Finite 4-replica (3 honest + 1 equivocating Byzantine, n=3f+1) 2-view BFT quorum-intersection, view-monotonicity, and lock-respect abstraction; does not model partial-synchrony liveness, Pacemaker GST timeouts, or BLS threshold signature aggregation.")
