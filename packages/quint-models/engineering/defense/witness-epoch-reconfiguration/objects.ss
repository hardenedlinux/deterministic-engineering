;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Business Extension B10b (10.171): Dynamic Witness Roster Reconfiguration,
;;; Joint-Consensus Dual-Quorum Handover (Q_old ∩ Q_new), and Forward-Secure
;;; Epoch Sealing Against Long-Range / Posterior-Corruption Attacks.
;;; Proves three dynamic reconfiguration & long-range safety invariants:
;;;   1. Joint-Consensus Dual-Quorum Handover: Epoch 2 never activates unless BOTH
;;;      a 2f+1 quorum of C_old AND a 2f+1 quorum of C_new ratify the handover
;;;      (unilateralHandoverViolations == 0).
;;;   2. Anchored History Continuity: Epoch 2 never finalizes a checkpoint without
;;;      verified RFC 6962 append-only consistency from Epoch 1's pinned anchor root
;;;      (unanchoredEpoch2Violations == 0).
;;;   3. Monotonic Pinned Epoch / Anti-Long-Range Forking: once Epoch 2 is pinned,
;;;      posterior compromise of retired Epoch 1 keys can NEVER introduce a conflicting
;;;      Epoch 1 fork (not (and epoch2CleanFinalized epoch1PostHandoverForkAccepted)
;;;      and longRangeRewriteViolations == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export WitnessEpochReconfigurationModel)

(.def (WitnessEpochReconfigurationModel @ ThreatModel.)
  identity: 'engineering.defense.witness-epoch-reconfiguration
  family: 'engineering.defense.witness-epoch-reconfiguration
  title: "Dynamic Witness Roster Reconfiguration, Dual-Quorum Handover & Forward-Secure Epoch Sealing"
  subdomain: 'quint.engineering.defense
  papers:
  '(("D. Ongaro & J. Ousterhout (USENIX ATC 2014)"
     "In Search of an Understandable Consensus Algorithm (Raft): §6 Joint Consensus C_{old,new} dual-quorum reconfiguration.")
    ("M. Bellare & S. K. Miner (CRYPTO 1999) / E. Deirmentzoglou et al. (IEEE Access 2019)"
     "Forward-Secure Digital Signatures and Long-Range / Posterior-Corruption Attacks in Long-Lived Ledgers.")
    ("Deterministic Engineering (10.169 / 10.171)"
     "Dynamic BFT witness committee handover with RFC 6962 anchor continuity, R3 retired-key zeroization, and monotonic weak-subjectivity pinning."))
  quint-module: "witness_epoch_reconfiguration"
  quint-file: "WitnessEpochReconfiguration.qnt"
  domain-dir: "engineering/defense/witness-epoch-reconfiguration"
  rules:
  '((witness-epoch-reconfig-safe DE-WER-SAFE quint)
    (witness-epoch-reconfig-countermodel DE-WER-COUNTER quint))
  dependencies:
  '((DE-WER-SAFE source)
    (DE-WER-SAFE profile)
    (DE-WER-SAFE method)
    (DE-WER-COUNTER source)
    (DE-WER-COUNTER profile)
    (DE-WER-COUNTER method))
  invariant: "Epoch 2 handover requires BOTH Q_old and Q_new ratification (unilateralHandoverViolations == 0), Epoch 2 checkpoint finality requires RFC 6962 anchor consistency from Epoch 1 (unanchoredEpoch2Violations == 0), and once Epoch 2 is pinned, posterior compromise of retired Epoch 1 keys cannot introduce a post-handover Epoch 1 fork (not(epoch2CleanFinalized and epoch1PostHandoverForkAccepted) and longRangeRewriteViolations == 0)."
  limits: "Two-epoch (Epoch 1 -> Epoch 2) dynamic committee handover abstraction; assumes offline/out-of-band verifier pinning of the handover epoch (weak subjectivity) to defeat posterior corruption of retired Epoch 1 keys.")
