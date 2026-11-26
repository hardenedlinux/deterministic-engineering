;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Business Extension B8 (10.165): Durable Memory-Poisoning Defense,
;;; Independent Quorum Fact Promotion, and Doyle/ATMS Causal Belief Retraction.
;;; Proves three long-horizon durable AI memory safety invariants:
;;;   1. Unverified/untrusted claims stay quarantined in M2 provisional memory
;;;      and can never enter M1 verified memory (poisonedPromotionViolations == 0).
;;;   2. Retracted poisoned claims are permanently immunized against re-ingestion
;;;      (repoisoningViolations == 0).
;;;   3. Causal TMS retraction invalidates single-support derived beliefs while
;;;      preserving ATMS beliefs backed by an independent clean justification
;;;      (zombieDerivedViolations == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export DurableMemoryTmsModel
        PoisonedPromotionCountermodel
        RepoisoningCountermodel
        ZombieDerivedReadCountermodel)

(.def (DurableMemoryTmsModel @ ThreatModel.)
  identity: 'engineering.defense.durable-memory-tms
  family: 'engineering.defense.durable-memory-tms
  title: "Durable Memory-Poisoning Defense: Quorum Promotion & ATMS Causal Retraction"
  subdomain: 'quint.engineering.defense
  papers:
  '(("J. Doyle (Artificial Intelligence 1979) / J. de Kleer (AIJ 1986)"
     "A Truth Maintenance System (TMS) & Assumption-Based TMS (ATMS): causal justification graphs and multi-support belief revision.")
    ("D. Malkhi & M. Reiter (Distributed Computing 1998)"
     "Byzantine Quorum Systems for independent multi-witness fact attestation.")
    ("Deterministic Engineering (10.156 / 10.165)"
     "Two-tier M2 provisional vs. M1 verified durable AI memory with causal retraction and poison-immunization tombstones."))
  quint-module: "durable_memory_tms"
  quint-file: "DurableMemoryTms.qnt"
  domain-dir: "engineering/defense/durable-memory-tms"
  verify-depth: 10
  countermodel-depth: 7
  rules:
  '((durable-memory-tms-safe DE-TMS-SAFE quint)
    (durable-memory-tms-countermodel DE-TMS-COUNTER quint))
  dependencies:
  '((DE-TMS-SAFE source)
    (DE-TMS-SAFE profile)
    (DE-TMS-SAFE method)
    (DE-TMS-COUNTER source)
    (DE-TMS-COUNTER profile)
    (DE-TMS-COUNTER method))
  invariant: "No unverified or untrusted claim enters M1 verified memory (poisonedPromotionViolations == 0), no retracted poisoned claim is re-ingested (repoisoningViolations == 0), and no derived belief lacking a surviving clean justification is read after root retraction (zombieDerivedViolations == 0)."
  parameters: '()
  state:
  '((sourceTrusted "bool" "false")
    (quorumMet "bool" "false")
    (rootPromoted "bool" "false")
    (derivedCreated "bool" "false")
    (derivedActive "bool" "false")
    (hasAltJustification "bool" "false")
    (rootRetracted "bool" "false")
    (poisonedPromotionViolations "int" "0")
    (repoisoningViolations "int" "0")
    (zombieDerivedViolations "int" "0")
    (validReads "int" "0"))
  guards:
  '((require-quorum-and-trusted-source (and (. h sourceTrusted) (. h quorumMet)))
    (forbid-repoisoning-retracted (not (. h rootRetracted)))
    (forbid-zombie-retracted-derived
      (and (. h derivedActive) (or (not (. h rootRetracted)) (. h hasAltJustification)))))
  transitions:
  '((markSourceTrusted
      (action markSourceTrusted ()
        (if (not (. h sourceTrusted))
          (set-h (sourceTrusted #t))
          (keep-h))))
    (achieveIndependentQuorum
      (action achieveIndependentQuorum ()
        (if (not (. h quorumMet))
          (set-h (quorumMet #t))
          (keep-h))))
    (promoteRootBelief
      (action promoteRootBelief ()
        (if (and (not (. h rootPromoted))
                 (guard require-quorum-and-trusted-source
                   (and (. h sourceTrusted) (. h quorumMet)))
                 (guard forbid-repoisoning-retracted (not (. h rootRetracted))))
          (set-h (rootPromoted #t)
                 (poisonedPromotionViolations
                   (if (and (. h sourceTrusted) (. h quorumMet))
                     (. h poisonedPromotionViolations)
                     (+ (. h poisonedPromotionViolations) 1)))
                 (repoisoningViolations
                   (if (not (. h rootRetracted))
                     (. h repoisoningViolations)
                     (+ (. h repoisoningViolations) 1))))
          (keep-h))))
    (deriveDependentBelief
      (action deriveDependentBelief ()
        (if (and (. h rootPromoted) (not (. h derivedCreated)))
          (set-h (derivedCreated #t) (derivedActive #t))
          (keep-h))))
    (attachAltCleanJustification
      (action attachAltCleanJustification ()
        (if (and (. h derivedCreated) (not (. h hasAltJustification)))
          (set-h (hasAltJustification #t) (derivedActive #t))
          (keep-h))))
    (retractPoisonedRoot
      (action retractPoisonedRoot ()
        (if (and (. h rootPromoted) (not (. h rootRetracted)))
          (set-h (rootRetracted #t)
                 (rootPromoted #f)
                 (derivedActive
                   (if (. h hasAltJustification)
                     (. h derivedActive)
                     #f)))
          (keep-h))))
    (readDerivedBelief
      (action readDerivedBelief ()
        (if (and (. h derivedCreated)
                 (guard forbid-zombie-retracted-derived
                   (and (. h derivedActive)
                        (or (not (. h rootRetracted)) (. h hasAltJustification)))))
          (set-h (validReads (+ (. h validReads) 1))
                 (zombieDerivedViolations
                   (if (and (. h derivedActive)
                            (or (not (. h rootRetracted)) (. h hasAltJustification)))
                     (. h zombieDerivedViolations)
                     (+ (. h zombieDerivedViolations) 1))))
          (keep-h))))
    (step
      (action step ()
        (any markSourceTrusted achieveIndependentQuorum promoteRootBelief
             deriveDependentBelief attachAltCleanJustification retractPoisonedRoot
             readDerivedBelief))))
  safety:
  '(and (= (. h poisonedPromotionViolations) 0)
        (= (. h repoisoningViolations) 0)
        (= (. h zombieDerivedViolations) 0))
  traces:
  '((atmsAltJustificationSurvivalTest
      (run atmsAltJustificationSurvivalTest
        (then init markSourceTrusted achieveIndependentQuorum promoteRootBelief
              deriveDependentBelief attachAltCleanJustification retractPoisonedRoot
              readDerivedBelief
              (all (assert safety)
                   (assert (. h rootRetracted))
                   (assert (. h derivedActive))
                   (assert (= (. h validReads) 1))
                   (keep-h)))))
    (poisonedPromotionViolatesSafetyTest
      (run poisonedPromotionViolatesSafetyTest
        (then init promoteUnverified
              (all (assert (not safety))
                   (assert (> (. h poisonedPromotionViolations) 0))
                   (keep-h)))))
    (repoisoningViolatesSafetyTest
      (run repoisoningViolatesSafetyTest
        (then init markSourceTrusted achieveIndependentQuorum promoteRootBelief
              retractPoisonedRoot repromoteRetracted
              (all (assert (not safety))
                   (assert (> (. h repoisoningViolations) 0))
                   (keep-h)))))
    (zombieDerivedReadViolatesSafetyTest
      (run zombieDerivedReadViolatesSafetyTest
        (then init markSourceTrusted achieveIndependentQuorum promoteRootBelief
              deriveDependentBelief retractPoisonedRoot readZombieDerived
              (all (assert (not safety))
                   (assert (> (. h zombieDerivedViolations) 0))
                   (keep-h))))))
  countermodels:
  (list PoisonedPromotionCountermodel
        RepoisoningCountermodel
        ZombieDerivedReadCountermodel)
  limits: "Finite single-root and single-derived ATMS belief revision abstraction; does not model probabilistic confidence calibration, contradictory belief resolution over cycles, or natural-language semantic equivalence beyond canonical claim digests.")

(.def (PoisonedPromotionCountermodel @ DurableMemoryTmsModel)
  identity: 'engineering.defense.durable-memory-tms.poisoned-promotion
  dropped-guard: 'require-quorum-and-trusted-source
  step-action: "stepPoisonedPromotion"
  derive-from-transition: 'promoteRootBelief
  derive-action-name: 'promoteUnverified
  expected-itf-predicate: "h.poisonedPromotionViolations > 0")

(.def (RepoisoningCountermodel @ DurableMemoryTmsModel)
  identity: 'engineering.defense.durable-memory-tms.repoisoning
  dropped-guard: 'forbid-repoisoning-retracted
  step-action: "stepRepoisoning"
  derive-from-transition: 'promoteRootBelief
  derive-action-name: 'repromoteRetracted
  expected-itf-predicate: "h.repoisoningViolations > 0")

(.def (ZombieDerivedReadCountermodel @ DurableMemoryTmsModel)
  identity: 'engineering.defense.durable-memory-tms.zombie-derived-read
  dropped-guard: 'forbid-zombie-retracted-derived
  step-action: "stepZombieDerivedRead"
  derive-from-transition: 'readDerivedBelief
  derive-action-name: 'readZombieDerived
  expected-itf-predicate: "h.zombieDerivedViolations > 0")
