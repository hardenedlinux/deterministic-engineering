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
(export WitnessEpochReconfigurationModel
        UnilateralHandoverCountermodel
        UnanchoredEpoch2Countermodel
        LongRangeForkCountermodel)

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
  verify-depth: 10
  countermodel-depth: 6
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
  parameters: '()
  state:
  '((activeEpoch "int" "1")
    (pinnedEpoch "int" "1")
    (epoch1CheckpointCount "int" "0")
    (oldQuorumSignedHandover "bool" "false")
    (newQuorumSignedHandover "bool" "false")
    (oldKeysZeroized "bool" "false")
    (oldKeysPosteriorCompromised "bool" "false")
    (anchorConsistencyVerified "bool" "false")
    (epoch2CleanFinalized "bool" "false")
    (epoch1PostHandoverForkAccepted "bool" "false")
    (unilateralHandoverViolations "int" "0")
    (unanchoredEpoch2Violations "int" "0")
    (longRangeRewriteViolations "int" "0"))
  guards:
  '((require-dual-quorum-handover (and (. h oldQuorumSignedHandover) (. h newQuorumSignedHandover)))
    (require-anchor-consistency-for-epoch2 (. h anchorConsistencyVerified))
    (enforce-monotonic-pinned-epoch (= (. h pinnedEpoch) 1)))
  transitions:
  '((acceptEpoch1Checkpoint
      (action acceptEpoch1Checkpoint ()
        (if (and (not (. h epoch1PostHandoverForkAccepted))
                 (or (= (. h epoch1CheckpointCount) 0) (>= (. h pinnedEpoch) 2))
                 (guard enforce-monotonic-pinned-epoch (= (. h pinnedEpoch) 1)))
          (set-h (epoch1CheckpointCount (+ (. h epoch1CheckpointCount) 1))
                 (epoch1PostHandoverForkAccepted
                   (if (= (. h pinnedEpoch) 1)
                     (. h epoch1PostHandoverForkAccepted)
                     #t))
                 (longRangeRewriteViolations
                   (if (= (. h pinnedEpoch) 1)
                     (. h longRangeRewriteViolations)
                     (+ (. h longRangeRewriteViolations) 1))))
          (keep-h))))
    (oldQuorumSignHandover
      (action oldQuorumSignHandover ()
        (if (not (. h oldQuorumSignedHandover))
          (set-h (oldQuorumSignedHandover #t))
          (keep-h))))
    (newQuorumSignHandover
      (action newQuorumSignHandover ()
        (if (not (. h newQuorumSignedHandover))
          (set-h (newQuorumSignedHandover #t))
          (keep-h))))
    (completeJointHandover
      (action completeJointHandover ()
        (if (and (= (. h activeEpoch) 1)
                 (guard require-dual-quorum-handover
                        (and (. h oldQuorumSignedHandover) (. h newQuorumSignedHandover))))
          (set-h (activeEpoch 2)
                 (pinnedEpoch 2)
                 (unilateralHandoverViolations
                   (if (and (. h oldQuorumSignedHandover) (. h newQuorumSignedHandover))
                     (. h unilateralHandoverViolations)
                     (+ (. h unilateralHandoverViolations) 1))))
          (keep-h))))
    (zeroizeRetiredOldKeys
      (action zeroizeRetiredOldKeys ()
        (if (and (>= (. h activeEpoch) 2) (not (. h oldKeysZeroized)))
          (set-h (oldKeysZeroized #t))
          (keep-h))))
    (adversaryCompromiseRetiredOldKeys
      (action adversaryCompromiseRetiredOldKeys ()
        (if (and (>= (. h activeEpoch) 2) (not (. h oldKeysPosteriorCompromised)))
          (set-h (oldKeysPosteriorCompromised #t))
          (keep-h))))
    (verifyEpoch2AnchorConsistency
      (action verifyEpoch2AnchorConsistency ()
        (if (and (>= (. h activeEpoch) 2) (not (. h anchorConsistencyVerified)))
          (set-h (anchorConsistencyVerified #t))
          (keep-h))))
    (finalizeEpoch2Checkpoint
      (action finalizeEpoch2Checkpoint ()
        (if (and (>= (. h activeEpoch) 2)
                 (not (. h epoch2CleanFinalized))
                 (guard require-anchor-consistency-for-epoch2 (. h anchorConsistencyVerified)))
          (set-h (epoch2CleanFinalized #t)
                 (unanchoredEpoch2Violations
                   (if (. h anchorConsistencyVerified)
                     (. h unanchoredEpoch2Violations)
                     (+ (. h unanchoredEpoch2Violations) 1))))
          (keep-h))))
    (step
      (action step ()
        (any acceptEpoch1Checkpoint oldQuorumSignHandover newQuorumSignHandover
             completeJointHandover zeroizeRetiredOldKeys adversaryCompromiseRetiredOldKeys
             verifyEpoch2AnchorConsistency finalizeEpoch2Checkpoint))))
  safety:
  '(and (not (and (. h epoch2CleanFinalized) (. h epoch1PostHandoverForkAccepted)))
        (= (. h unilateralHandoverViolations) 0)
        (= (. h unanchoredEpoch2Violations) 0)
        (= (. h longRangeRewriteViolations) 0))
  traces:
  '((jointHandoverAndForwardSealingTest
      (run jointHandoverAndForwardSealingTest
        (then init acceptEpoch1Checkpoint oldQuorumSignHandover newQuorumSignHandover
              completeJointHandover zeroizeRetiredOldKeys adversaryCompromiseRetiredOldKeys
              verifyEpoch2AnchorConsistency finalizeEpoch2Checkpoint acceptEpoch1Checkpoint
              (all (assert safety)
                   (assert (= (. h activeEpoch) 2))
                   (assert (. h epoch2CleanFinalized))
                   (assert (not (. h epoch1PostHandoverForkAccepted)))
                   (keep-h)))))
    (unilateralHandoverViolatesSafetyTest
      (run unilateralHandoverViolatesSafetyTest
        (then init oldQuorumSignHandover completeUnilateralHandover
              (all (assert (not safety))
                   (assert (> (. h unilateralHandoverViolations) 0))
                   (keep-h)))))
    (unanchoredEpoch2ViolatesSafetyTest
      (run unanchoredEpoch2ViolatesSafetyTest
        (then init oldQuorumSignHandover newQuorumSignHandover completeJointHandover
              finalizeEpoch2Unanchored
              (all (assert (not safety))
                   (assert (> (. h unanchoredEpoch2Violations) 0))
                   (keep-h)))))
    (longRangeForkViolatesSafetyTest
      (run longRangeForkViolatesSafetyTest
        (then init oldQuorumSignHandover newQuorumSignHandover completeJointHandover
              adversaryCompromiseRetiredOldKeys acceptEpoch1PostPin
              (all (assert (not safety))
                   (assert (> (. h longRangeRewriteViolations) 0))
                   (keep-h))))))
  countermodels:
  (list UnilateralHandoverCountermodel
        UnanchoredEpoch2Countermodel
        LongRangeForkCountermodel)
  limits: "Two-epoch (Epoch 1 -> Epoch 2) dynamic committee handover abstraction; assumes offline/out-of-band verifier pinning of the handover epoch (weak subjectivity) to defeat posterior corruption of retired Epoch 1 keys.")

(.def (UnilateralHandoverCountermodel @ WitnessEpochReconfigurationModel)
  identity: 'engineering.defense.witness-epoch-reconfiguration.unilateral-handover
  dropped-guard: 'require-dual-quorum-handover
  step-action: "stepUnilateralHandover"
  derive-from-transition: 'completeJointHandover
  derive-action-name: 'completeUnilateralHandover
  expected-itf-predicate: "h.unilateralHandoverViolations > 0")

(.def (UnanchoredEpoch2Countermodel @ WitnessEpochReconfigurationModel)
  identity: 'engineering.defense.witness-epoch-reconfiguration.unanchored-epoch2
  dropped-guard: 'require-anchor-consistency-for-epoch2
  step-action: "stepUnanchoredEpoch2"
  derive-from-transition: 'finalizeEpoch2Checkpoint
  derive-action-name: 'finalizeEpoch2Unanchored
  expected-itf-predicate: "h.unanchoredEpoch2Violations > 0")

(.def (LongRangeForkCountermodel @ WitnessEpochReconfigurationModel)
  identity: 'engineering.defense.witness-epoch-reconfiguration.long-range-fork
  dropped-guard: 'enforce-monotonic-pinned-epoch
  step-action: "stepLongRangeFork"
  derive-from-transition: 'acceptEpoch1Checkpoint
  derive-action-name: 'acceptEpoch1PostPin
  expected-itf-predicate: "h.longRangeRewriteViolations > 0")
