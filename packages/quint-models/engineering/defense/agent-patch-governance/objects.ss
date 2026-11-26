;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; G2 / G5 / M3: AI Agent Patch Admission & Bounded Anti-Evasion Repair Loop (10.155).
;;; Proves that an AI Agent's prose claim never substitutes for independent mechanical audit,
;;; that deleting a verification obligation in a diff blocks admission unless a replacement
;;; witness is admitted, that floor weakening during retry is refused, and that retry exhaustion
;;; escalates to human review rather than silently admitting.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export AgentPatchGovernanceModel
        SelfCertifiedAdmissionCountermodel
        SilentObligationDeletionCountermodel
        FloorWeakeningEvasionCountermodel)

(.def (AgentPatchGovernanceModel @ ThreatModel.)
  identity: 'engineering.defense.agent-patch-governance
  family: 'engineering.defense.agent-patch-governance
  title: "AI Agent Patch Admission & Bounded Anti-Evasion Repair Loop"
  subdomain: 'quint.engineering.defense
  papers:
  '(("Deterministic Engineering (10.18 / 10.153 / 10.155)"
     "Agent prose claims are assertions, never evidence; independent audit, obligation preservation, monotonic floors, and bounded human escalation.")
    ("Deterministic Engineering (30.05)"
     "Thirty-two-case five-language AI Agent defensive hallucination and anti-evasion benchmark."))
  quint-module: "agent_patch_governance"
  quint-file: "AgentPatchGovernance.qnt"
  domain-dir: "engineering/defense/agent-patch-governance"
  verify-depth: 10
  countermodel-depth: 6
  rules:
  '((agent-patch-safe DE-AGT-SAFE quint)
    (agent-patch-countermodel DE-AGT-COUNTER quint))
  dependencies:
  '((DE-AGT-SAFE source)
    (DE-AGT-SAFE profile)
    (DE-AGT-SAFE method)
    (DE-AGT-COUNTER source)
    (DE-AGT-COUNTER profile)
    (DE-AGT-COUNTER method))
  invariant: "Repair attempts stay within bound (repairAttempts <= 2), and no AI Agent patch reaches Admitted (decision == 1) without independent mechanical audit, intact Band-5 floors (not floorWeakened), and preserved or explicitly replaced verification obligations."
  parameters: '()
  state:
  '((patchProposed "bool" "false")
    (agentClaimsFixed "bool" "false")
    (independentAuditPassed "bool" "false")
    (obligationDeleted "bool" "false")
    (replacementAdmitted "bool" "false")
    (floorWeakened "bool" "false")
    (repairAttempts "int" "0")
    (decision "int" "0"))
  guards:
  '((require-independent-audit (. h independentAuditPassed))
    (forbid-unwitnessed-obligation-deletion (or (not (. h obligationDeleted)) (. h replacementAdmitted)))
    (forbid-floor-weakening-on-retry (not (. h floorWeakened))))
  transitions:
  '((proposePatch
      (action proposePatch ()
        (if (not (. h patchProposed))
          (set-h (patchProposed #t))
          (keep-h))))
    (agentClaimFixed
      (action agentClaimFixed ()
        (if (and (. h patchProposed) (not (. h agentClaimsFixed)))
          (set-h (agentClaimsFixed #t))
          (keep-h))))
    (passIndependentAudit
      (action passIndependentAudit ()
        (if (and (. h patchProposed) (= (. h decision) 0) (not (. h independentAuditPassed)) (not (. h floorWeakened)))
          (set-h (independentAuditPassed #t))
          (keep-h))))
    (deleteObligationInDiff
      (action deleteObligationInDiff ()
        (if (and (. h patchProposed) (= (. h decision) 0) (not (. h obligationDeleted)))
          (set-h (obligationDeleted #t))
          (keep-h))))
    (admitReplacementWitness
      (action admitReplacementWitness ()
        (if (and (. h obligationDeleted) (= (. h decision) 0) (not (. h replacementAdmitted)))
          (set-h (replacementAdmitted #t))
          (keep-h))))
    (attemptFloorWeakening
      (action attemptFloorWeakening ()
        (if (and (. h patchProposed) (= (. h decision) 0) (not (. h floorWeakened)))
          (set-h (floorWeakened #t))
          (keep-h))))
    (refuseAndRetry
      (action refuseAndRetry ()
        (if (and (. h patchProposed)
                 (= (. h decision) 0)
                 (< (. h repairAttempts) 2)
                 (or (not (. h independentAuditPassed))
                     (. h floorWeakened)
                     (and (. h obligationDeleted) (not (. h replacementAdmitted)))))
          (set-h (repairAttempts (+ (. h repairAttempts) 1))
                 (floorWeakened #f))
          (keep-h))))
    (escalateBudgetExhausted
      (action escalateBudgetExhausted ()
        (if (and (. h patchProposed) (= (. h decision) 0) (= (. h repairAttempts) 2))
          (set-h (decision 3))
          (keep-h))))
    (admitPatch
      (action admitPatch ()
        (if (and (. h patchProposed)
                 (= (. h decision) 0)
                 (guard require-independent-audit (. h independentAuditPassed))
                 (guard forbid-unwitnessed-obligation-deletion
                   (or (not (. h obligationDeleted)) (. h replacementAdmitted)))
                 (guard forbid-floor-weakening-on-retry (not (. h floorWeakened))))
          (set-h (decision 1))
          (keep-h))))
    (step
      (action step ()
        (any proposePatch agentClaimFixed passIndependentAudit
             deleteObligationInDiff admitReplacementWitness attemptFloorWeakening
             refuseAndRetry escalateBudgetExhausted admitPatch))))
  safety:
  '(and (<= (. h repairAttempts) 2)
        (or (!= (. h decision) 1)
            (and (. h independentAuditPassed)
                 (not (. h floorWeakened))
                 (or (not (. h obligationDeleted)) (. h replacementAdmitted)))))
  traces:
  '((verifiedPatchAdmittedSafeTest
      (run verifiedPatchAdmittedSafeTest
        (then init proposePatch agentClaimFixed passIndependentAudit admitPatch
              (all (assert safety)
                   (assert (= (. h decision) 1))
                   (keep-h)))))
    (budgetExhaustionEscalatesHumanSafeTest
      (run budgetExhaustionEscalatesHumanSafeTest
        (then init proposePatch agentClaimFixed attemptFloorWeakening refuseAndRetry refuseAndRetry escalateBudgetExhausted
              (all (assert safety)
                   (assert (= (. h decision) 3))
                   (assert (= (. h repairAttempts) 2))
                   (keep-h)))))
    (selfCertifiedViolatesSafetyTest
      (run selfCertifiedViolatesSafetyTest
        (then init proposePatch agentClaimFixed admitPatchSelfCertified
              (all (assert (not safety))
                   (assert (= (. h decision) 1))
                   (assert (not (. h independentAuditPassed)))
                   (keep-h)))))
    (deletedObligationViolatesSafetyTest
      (run deletedObligationViolatesSafetyTest
        (then init proposePatch passIndependentAudit deleteObligationInDiff admitPatchDeletedObligation
              (all (assert (not safety))
                   (assert (= (. h decision) 1))
                   (assert (. h obligationDeleted))
                   (assert (not (. h replacementAdmitted)))
                   (keep-h)))))
    (floorWeakeningViolatesSafetyTest
      (run floorWeakeningViolatesSafetyTest
        (then init proposePatch passIndependentAudit attemptFloorWeakening admitPatchWeakenedFloor
              (all (assert (not safety))
                   (assert (= (. h decision) 1))
                   (assert (. h floorWeakened))
                   (keep-h))))))
  countermodels:
  (list SelfCertifiedAdmissionCountermodel
        SilentObligationDeletionCountermodel
        FloorWeakeningEvasionCountermodel)
  limits: "Finite single-patch governance loop with bounded retry budget (max 2 retries); does not model multi-PR merge conflicts, compromised CI runners, or adversarial oracle poisoning.")

(.def (SelfCertifiedAdmissionCountermodel @ AgentPatchGovernanceModel)
  identity: 'engineering.defense.agent-patch-governance.self-certified
  dropped-guard: 'require-independent-audit
  step-action: "stepSelfCertified"
  derive-from-transition: 'admitPatch
  derive-action-name: 'admitPatchSelfCertified
  expected-itf-predicate: "h.decision == 1 and not(h.independentAuditPassed)")

(.def (SilentObligationDeletionCountermodel @ AgentPatchGovernanceModel)
  identity: 'engineering.defense.agent-patch-governance.deleted-obligation
  dropped-guard: 'forbid-unwitnessed-obligation-deletion
  step-action: "stepDeletedObligation"
  derive-from-transition: 'admitPatch
  derive-action-name: 'admitPatchDeletedObligation
  expected-itf-predicate: "h.decision == 1 and h.obligationDeleted and not(h.replacementAdmitted)")

(.def (FloorWeakeningEvasionCountermodel @ AgentPatchGovernanceModel)
  identity: 'engineering.defense.agent-patch-governance.floor-weakening
  dropped-guard: 'forbid-floor-weakening-on-retry
  step-action: "stepFloorWeakening"
  derive-from-transition: 'admitPatch
  derive-action-name: 'admitPatchWeakenedFloor
  expected-itf-predicate: "h.decision == 1 and h.floorWeakened")
