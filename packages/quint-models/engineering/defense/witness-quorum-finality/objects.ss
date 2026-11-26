;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Business Extension B10 (10.169): Proactive Threshold Witness Cosigning
;;; (t = 2f + 1 of N = 3f + 1), Quorum Intersection Safety, and Eclipse-Resistant
;;; Checkpoint Finality.
;;; Proves three BFT transparency finality invariants under N = 4, f = 1, t = 3:
;;;   1. Quorum Intersection Safety: even with 1 Byzantine witness freely double-signing
;;;      BOTH branches, conflicting Clean and Backdoor checkpoints can NEVER both finalize
;;;      (not (and cleanFinalized backdoorFinalized)).
;;;   2. Consistency-Before-Cosign: honest witnesses never cosign without verified RFC 6962
;;;      append-only consistency (unverifiedCosignViolations == 0).
;;;   3. Threshold Quorum & Non-Equivocation: no checkpoint finalizes below 2f + 1 = 3
;;;      distinct witness cosignatures and no honest witness double-signs
;;;      (subQuorumViolations == 0 and honestEquivocationViolations == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export WitnessQuorumFinalityModel
        UnverifiedCosignCountermodel
        HonestEquivocationCountermodel
        SubQuorumFinalizationCountermodel)

(.def (WitnessQuorumFinalityModel @ ThreatModel.)
  identity: 'engineering.defense.witness-quorum-finality
  family: 'engineering.defense.witness-quorum-finality
  title: "Proactive Threshold Witness Cosigning (2f+1 of 3f+1) & Quorum Intersection Finality"
  subdomain: 'quint.engineering.defense
  papers:
  '(("M. Castro & B. Liskov (USENIX OSDI 1999) / M. Yin et al. (ACM PODC 2019)"
     "PBFT & HotStuff: 2f+1 Quorum Certificates guaranteeing intersection of at least one honest replica.")
    ("E. Syta et al. (IEEE S&P 2016)"
     "Keeping Authorities 'Honest or Bust' with Decentralized Witness Cosigning (CoSi).")
    ("Deterministic Engineering (10.166 / 10.169)"
     "Proactive offline-verifiable Ed25519 witness cosigning blocking split-view even under total network eclipse."))
  quint-module: "witness_quorum_finality"
  quint-file: "WitnessQuorumFinality.qnt"
  domain-dir: "engineering/defense/witness-quorum-finality"
  verify-depth: 10
  countermodel-depth: 6
  rules:
  '((witness-quorum-safe DE-WQC-SAFE quint)
    (witness-quorum-countermodel DE-WQC-COUNTER quint))
  dependencies:
  '((DE-WQC-SAFE source)
    (DE-WQC-SAFE profile)
    (DE-WQC-SAFE method)
    (DE-WQC-COUNTER source)
    (DE-WQC-COUNTER profile)
    (DE-WQC-COUNTER method))
  invariant: "With N=4 witnesses (3 honest + 1 Byzantine double-signer) and threshold t=3 (2f+1), conflicting clean and backdoor branches can never both finalize (not(cleanFinalized and backdoorFinalized)), no honest witness cosigns without RFC 6962 consistency (unverifiedCosignViolations == 0) or double-signs (honestEquivocationViolations == 0), and no checkpoint finalizes below quorum (subQuorumViolations == 0)."
  parameters: '()
  state:
  '((w1Branch "int" "0")
    (w2Branch "int" "0")
    (w3Branch "int" "0")
    (byzClean "bool" "false")
    (byzBackdoor "bool" "false")
    (consistencyOk "bool" "false")
    (cleanVotes "int" "0")
    (backdoorVotes "int" "0")
    (cleanFinalized "bool" "false")
    (backdoorFinalized "bool" "false")
    (unverifiedCosignViolations "int" "0")
    (honestEquivocationViolations "int" "0")
    (subQuorumViolations "int" "0"))
  guards:
  '((require-consistency-before-cosign (. h consistencyOk))
    (forbid-honest-double-sign (= (. h w1Branch) 0))
    (enforce-quorum-2f1 (>= (. h cleanVotes) 3)))
  transitions:
  '((verifyConsistencyProof
      (action verifyConsistencyProof ()
        (if (not (. h consistencyOk))
          (set-h (consistencyOk #t))
          (keep-h))))
    (w1CosignClean
      (action w1CosignClean ()
        (if (and (!= (. h w1Branch) 1)
                 (guard require-consistency-before-cosign (. h consistencyOk))
                 (guard forbid-honest-double-sign (= (. h w1Branch) 0)))
          (set-h (w1Branch 1)
                 (cleanVotes (+ (. h cleanVotes) 1))
                 (unverifiedCosignViolations
                   (if (. h consistencyOk)
                     (. h unverifiedCosignViolations)
                     (+ (. h unverifiedCosignViolations) 1)))
                 (honestEquivocationViolations
                   (if (= (. h w1Branch) 0)
                     (. h honestEquivocationViolations)
                     (+ (. h honestEquivocationViolations) 1))))
          (keep-h))))
    (w1CosignBackdoor
      (action w1CosignBackdoor ()
        (if (and (. h consistencyOk) (= (. h w1Branch) 0))
          (set-h (w1Branch 2)
                 (backdoorVotes (+ (. h backdoorVotes) 1)))
          (keep-h))))
    (w2CosignClean
      (action w2CosignClean ()
        (if (= (. h w2Branch) 0)
          (set-h (w2Branch 1)
                 (cleanVotes (+ (. h cleanVotes) 1)))
          (keep-h))))
    (w3CosignBackdoor
      (action w3CosignBackdoor ()
        (if (= (. h w3Branch) 0)
          (set-h (w3Branch 2)
                 (backdoorVotes (+ (. h backdoorVotes) 1)))
          (keep-h))))
    (byzW4DoubleSignBoth
      (action byzW4DoubleSignBoth ()
        (if (or (not (. h byzClean)) (not (. h byzBackdoor)))
          (set-h (byzClean #t)
                 (byzBackdoor #t)
                 (cleanVotes (if (. h byzClean) (. h cleanVotes) (+ (. h cleanVotes) 1)))
                 (backdoorVotes (if (. h byzBackdoor) (. h backdoorVotes) (+ (. h backdoorVotes) 1))))
          (keep-h))))
    (finalizeClean
      (action finalizeClean ()
        (if (and (not (. h cleanFinalized))
                 (guard enforce-quorum-2f1 (>= (. h cleanVotes) 3)))
          (set-h (cleanFinalized #t)
                 (subQuorumViolations
                   (if (>= (. h cleanVotes) 3)
                     (. h subQuorumViolations)
                     (+ (. h subQuorumViolations) 1))))
          (keep-h))))
    (finalizeBackdoor
      (action finalizeBackdoor ()
        (if (and (not (. h backdoorFinalized))
                 (>= (. h backdoorVotes) 3))
          (set-h (backdoorFinalized #t))
          (keep-h))))
    (step
      (action step ()
        (any verifyConsistencyProof w1CosignClean w1CosignBackdoor
             w2CosignClean w3CosignBackdoor byzW4DoubleSignBoth
             finalizeClean finalizeBackdoor))))
  safety:
  '(and (not (and (. h cleanFinalized) (. h backdoorFinalized)))
        (= (. h unverifiedCosignViolations) 0)
        (= (. h honestEquivocationViolations) 0)
        (= (. h subQuorumViolations) 0))
  traces:
  '((quorumIntersectionPreventsConflictingFinalityTest
      (run quorumIntersectionPreventsConflictingFinalityTest
        (then init verifyConsistencyProof w1CosignClean w2CosignClean
              byzW4DoubleSignBoth w3CosignBackdoor finalizeClean finalizeBackdoor
              (all (assert safety)
                   (assert (. h cleanFinalized))
                   (assert (not (. h backdoorFinalized)))
                   (keep-h)))))
    (unverifiedCosignViolatesSafetyTest
      (run unverifiedCosignViolatesSafetyTest
        (then init w1CosignUnverified
              (all (assert (not safety))
                   (assert (> (. h unverifiedCosignViolations) 0))
                   (keep-h)))))
    (honestEquivocationViolatesSafetyTest
      (run honestEquivocationViolatesSafetyTest
        (then init verifyConsistencyProof w1CosignBackdoor w1DoubleSignClean
              (all (assert (not safety))
                   (assert (> (. h honestEquivocationViolations) 0))
                   (keep-h)))))
    (subQuorumViolatesSafetyTest
      (run subQuorumViolatesSafetyTest
        (then init finalizeCleanSubQuorum
              (all (assert (not safety))
                   (assert (> (. h subQuorumViolations) 0))
                   (keep-h))))))
  countermodels:
  (list UnverifiedCosignCountermodel
        HonestEquivocationCountermodel
        SubQuorumFinalizationCountermodel)
  limits: "Finite N=4 (f=1, t=3) Byzantine witness cosigning quorum-intersection abstraction; assumes static witness roster and <= f compromised witnesses (safety breaks if > f witnesses collude).")

(.def (UnverifiedCosignCountermodel @ WitnessQuorumFinalityModel)
  identity: 'engineering.defense.witness-quorum-finality.unverified-cosign
  dropped-guard: 'require-consistency-before-cosign
  step-action: "stepUnverifiedCosign"
  derive-from-transition: 'w1CosignClean
  derive-action-name: 'w1CosignUnverified
  expected-itf-predicate: "h.unverifiedCosignViolations > 0")

(.def (HonestEquivocationCountermodel @ WitnessQuorumFinalityModel)
  identity: 'engineering.defense.witness-quorum-finality.honest-equivocation
  dropped-guard: 'forbid-honest-double-sign
  step-action: "stepHonestEquivocation"
  derive-from-transition: 'w1CosignClean
  derive-action-name: 'w1DoubleSignClean
  expected-itf-predicate: "h.honestEquivocationViolations > 0")

(.def (SubQuorumFinalizationCountermodel @ WitnessQuorumFinalityModel)
  identity: 'engineering.defense.witness-quorum-finality.sub-quorum
  dropped-guard: 'enforce-quorum-2f1
  step-action: "stepSubQuorum"
  derive-from-transition: 'finalizeClean
  derive-action-name: 'finalizeCleanSubQuorum
  expected-itf-predicate: "h.subQuorumViolations > 0")
