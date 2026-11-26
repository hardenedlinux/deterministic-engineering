;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Business Extension B5 (10.159): Long-Horizon Human-in-the-Loop (HITL)
;;; Durable Pause/Resume, Baseline/Policy-Drift Re-Approval, Cold Hibernation,
;;; and Anti-Nagging Veto Persistence.
;;; Proves three critical governance invariants across multi-day human think-time:
;;;   1. Stale approvals invalidated by baseline drift, policy upgrade, or TTL expiry
;;;      can never execute upon wake-up (staleExecutions == 0).
;;;   2. Human veto is permanently binding and single-use approval receipts cannot
;;;      be replayed across duplicate webhooks or retries (vetoOrReplayViolations == 0,
;;;      executedCount <= 1).
;;;   3. Suspended agents must enter M1-only cold hibernation with zero leaked M3
;;;      live leases/capabilities across pause (m3LeakViolations == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export HitlDurableApprovalModel
        StaleDriftResumeCountermodel
        VetoOrReplayResumeCountermodel
        LeakedM3ResumeCountermodel)

(.def (HitlDurableApprovalModel @ ThreatModel.)
  identity: 'engineering.defense.hitl-durable-approval
  family: 'engineering.defense.hitl-durable-approval
  title: "Human-in-the-Loop Durable Pause/Resume, Policy-Drift Re-Approval & Anti-Nagging Veto"
  subdomain: 'quint.engineering.defense
  papers:
  '(("M. Atkinson & R. Morrison (VLDB J. 1995) / J. Shapiro (KeyKOS/EROS)"
     "Orthogonal persistence vs. non-persistent capability revocation across long-horizon hibernation.")
    ("Deterministic Engineering (10.156 / 10.157 / 10.159)"
     "Cryptographically bound M1 human approval receipts, cold hibernation, drift revalidation, and anti-nagging veto persistence."))
  quint-module: "hitl_durable_approval"
  quint-file: "HitlDurableApproval.qnt"
  domain-dir: "engineering/defense/hitl-durable-approval"
  verify-depth: 10
  countermodel-depth: 6
  rules:
  '((hitl-approval-safe DE-HITL-SAFE quint)
    (hitl-approval-countermodel DE-HITL-COUNTER quint))
  dependencies:
  '((DE-HITL-SAFE source)
    (DE-HITL-SAFE profile)
    (DE-HITL-SAFE method)
    (DE-HITL-COUNTER source)
    (DE-HITL-COUNTER profile)
    (DE-HITL-COUNTER method))
  invariant: "No suspended agent resumes with a stale approval after baseline drift, policy upgrade, or TTL expiry (staleExecutions == 0), no human-vetoed or already-consumed approval executes (vetoOrReplayViolations == 0 and executedCount <= 1), and no execution resumes from a dirty hibernation that leaked live M3 leases (m3LeakViolations == 0)."
  parameters: '()
  state:
  '((authorId "int" "1")
    (approverId "int" "0")
    (suspended "bool" "false")
    (m3LeaseLeaked "bool" "false")
    (baselineVersion "int" "1")
    (policyEpoch "int" "1")
    (approvedBaseline "int" "0")
    (approvedPolicyEpoch "int" "0")
    (approvalExpired "bool" "false")
    (humanVetoed "bool" "false")
    (executedCount "int" "0")
    (staleExecutions "int" "0")
    (vetoOrReplayViolations "int" "0")
    (m3LeakViolations "int" "0"))
  guards:
  '((require-fresh-m1-binding
      (and (!= (. h approverId) 0)
           (!= (. h approverId) (. h authorId))
           (= (. h approvedBaseline) (. h baselineVersion))
           (= (. h approvedPolicyEpoch) (. h policyEpoch))
           (not (. h approvalExpired))))
    (forbid-vetoed-or-replayed-execution
      (and (not (. h humanVetoed)) (= (. h executedCount) 0)))
    (require-cold-hibernation-clean
      (and (. h suspended) (not (. h m3LeaseLeaked)))))
  transitions:
  '((suspendCold
      (action suspendCold ()
        (if (not (. h suspended))
          (set-h (suspended #t) (m3LeaseLeaked #f))
          (keep-h))))
    (suspendWithLeakedM3
      (action suspendWithLeakedM3 ()
        (if (and (not (. h suspended)) (not (. h m3LeaseLeaked)))
          (set-h (suspended #t) (m3LeaseLeaked #t))
          (keep-h))))
    (humanApproveCurrent
      (action humanApproveCurrent ()
        (if (and (. h suspended) (not (. h humanVetoed)) (= (. h executedCount) 0))
          (set-h (approverId 2)
                 (approvedBaseline (. h baselineVersion))
                 (approvedPolicyEpoch (. h policyEpoch))
                 (approvalExpired #f))
          (keep-h))))
    (humanVetoProposal
      (action humanVetoProposal ()
        (if (and (. h suspended) (not (. h humanVetoed)))
          (set-h (humanVetoed #t))
          (keep-h))))
    (baselineDriftsDuringPause
      (action baselineDriftsDuringPause ()
        (if (and (. h suspended) (< (. h baselineVersion) 3))
          (set-h (baselineVersion (+ (. h baselineVersion) 1)))
          (keep-h))))
    (policyUpgradesDuringPause
      (action policyUpgradesDuringPause ()
        (if (and (. h suspended) (< (. h policyEpoch) 3))
          (set-h (policyEpoch (+ (. h policyEpoch) 1)))
          (keep-h))))
    (approvalTtlExpires
      (action approvalTtlExpires ()
        (if (and (!= (. h approverId) 0) (not (. h approvalExpired)))
          (set-h (approvalExpired #t))
          (keep-h))))
    (resumeAndExecute
      (action resumeAndExecute ()
        (if (and (guard require-fresh-m1-binding
                   (and (!= (. h approverId) 0)
                        (!= (. h approverId) (. h authorId))
                        (= (. h approvedBaseline) (. h baselineVersion))
                        (= (. h approvedPolicyEpoch) (. h policyEpoch))
                        (not (. h approvalExpired))))
                 (guard forbid-vetoed-or-replayed-execution
                   (and (not (. h humanVetoed)) (= (. h executedCount) 0)))
                 (guard require-cold-hibernation-clean
                   (and (. h suspended) (not (. h m3LeaseLeaked)))))
          (set-h (executedCount (+ (. h executedCount) 1))
                 (staleExecutions
                   (if (and (!= (. h approverId) 0)
                            (!= (. h approverId) (. h authorId))
                            (= (. h approvedBaseline) (. h baselineVersion))
                            (= (. h approvedPolicyEpoch) (. h policyEpoch))
                            (not (. h approvalExpired)))
                     (. h staleExecutions)
                     (+ (. h staleExecutions) 1)))
                 (vetoOrReplayViolations
                   (if (and (not (. h humanVetoed)) (= (. h executedCount) 0))
                     (. h vetoOrReplayViolations)
                     (+ (. h vetoOrReplayViolations) 1)))
                 (m3LeakViolations
                   (if (and (. h suspended) (not (. h m3LeaseLeaked)))
                     (. h m3LeakViolations)
                     (+ (. h m3LeakViolations) 1))))
          (keep-h))))
    (step
      (action step ()
        (any suspendCold suspendWithLeakedM3 humanApproveCurrent humanVetoProposal
             baselineDriftsDuringPause policyUpgradesDuringPause approvalTtlExpires
             resumeAndExecute))))
  safety:
  '(and (= (. h staleExecutions) 0)
        (= (. h vetoOrReplayViolations) 0)
        (= (. h m3LeakViolations) 0)
        (<= (. h executedCount) 1))
  traces:
  '((driftReapprovalAndSafeResumeTest
      (run driftReapprovalAndSafeResumeTest
        (then init suspendCold humanApproveCurrent baselineDriftsDuringPause
              policyUpgradesDuringPause humanApproveCurrent resumeAndExecute
              (all (assert safety)
                   (assert (= (. h executedCount) 1))
                   (assert (= (. h approvedBaseline) 2))
                   (assert (= (. h approvedPolicyEpoch) 2))
                   (keep-h)))))
    (staleDriftBypassViolatesSafetyTest
      (run staleDriftBypassViolatesSafetyTest
        (then init suspendCold humanApproveCurrent baselineDriftsDuringPause resumeStaleDrift
              (all (assert (not safety))
                   (assert (> (. h staleExecutions) 0))
                   (keep-h)))))
    (vetoBypassViolatesSafetyTest
      (run vetoBypassViolatesSafetyTest
        (then init suspendCold humanApproveCurrent humanVetoProposal resumeIgnoreVetoOrReplay
              (all (assert (not safety))
                   (assert (> (. h vetoOrReplayViolations) 0))
                   (keep-h)))))
    (leakedM3ResumeViolatesSafetyTest
      (run leakedM3ResumeViolatesSafetyTest
        (then init suspendWithLeakedM3 humanApproveCurrent resumeWithLeakedM3
              (all (assert (not safety))
                   (assert (> (. h m3LeakViolations) 0))
                   (keep-h))))))
  countermodels:
  (list StaleDriftResumeCountermodel
        VetoOrReplayResumeCountermodel
        LeakedM3ResumeCountermodel)
  limits: "Finite single-proposal HITL pause/resume, baseline/policy drift, TTL expiry, and cold-hibernation abstraction; does not model multi-region quorum clock skew, interactive UI phishing outside the M1 brief, or external webhook transport encryption.")

(.def (StaleDriftResumeCountermodel @ HitlDurableApprovalModel)
  identity: 'engineering.defense.hitl-durable-approval.stale-drift
  dropped-guard: 'require-fresh-m1-binding
  step-action: "stepStaleDriftBypass"
  derive-from-transition: 'resumeAndExecute
  derive-action-name: 'resumeStaleDrift
  expected-itf-predicate: "h.staleExecutions > 0")

(.def (VetoOrReplayResumeCountermodel @ HitlDurableApprovalModel)
  identity: 'engineering.defense.hitl-durable-approval.veto-or-replay
  dropped-guard: 'forbid-vetoed-or-replayed-execution
  step-action: "stepVetoOrReplayBypass"
  derive-from-transition: 'resumeAndExecute
  derive-action-name: 'resumeIgnoreVetoOrReplay
  expected-itf-predicate: "h.vetoOrReplayViolations > 0")

(.def (LeakedM3ResumeCountermodel @ HitlDurableApprovalModel)
  identity: 'engineering.defense.hitl-durable-approval.leaked-m3
  dropped-guard: 'require-cold-hibernation-clean
  step-action: "stepLeakedM3Resume"
  derive-from-transition: 'resumeAndExecute
  derive-action-name: 'resumeWithLeakedM3
  expected-itf-predicate: "h.m3LeakViolations > 0")
