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
(export HitlDurableApprovalModel)

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
  limits: "Finite single-proposal HITL pause/resume, baseline/policy drift, TTL expiry, and cold-hibernation abstraction; does not model multi-region quorum clock skew, interactive UI phishing outside the M1 brief, or external webhook transport encryption.")
