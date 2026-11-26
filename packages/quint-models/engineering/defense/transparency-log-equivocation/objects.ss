;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Business Extension B9 (10.166): Verifiable Append-Only Transparency Log,
;;; RFC 6962 Consistency Proofs, Ed25519 Signed Tree Heads, and Split-View
;;; Equivocation Fraud Proofs against a Compromised Coordinator.
;;; Proves three cryptographic transparency invariants:
;;;   1. No audit entry is accepted without a verified RFC 6962 inclusion proof
;;;      (unverifiedEntryAccepts == 0).
;;;   2. No updated Signed Tree Head is accepted if it fails RFC 6962 append-only
;;;      consistency (historyRewriteAccepts == 0).
;;;   3. No audit snapshot is accepted when witness gossip detects split-view
;;;      equivocation by the coordinator (equivocationAccepts == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export TransparencyLogEquivocationModel
        UnverifiedInclusionCountermodel
        HistoryRewriteCountermodel
        SplitViewEquivocationCountermodel)

(.def (TransparencyLogEquivocationModel @ ThreatModel.)
  identity: 'engineering.defense.transparency-log-equivocation
  family: 'engineering.defense.transparency-log-equivocation
  title: "Verifiable Transparency Log: RFC 6962 Consistency & Split-View Equivocation Defense"
  subdomain: 'quint.engineering.defense
  papers:
  '(("B. Laurie, A. Langley & E. Kasper (RFC 6962 / ACM Queue 2014)"
     "Certificate Transparency: O(log N) Merkle inclusion & append-only consistency proofs.")
    ("M. Syta et al. (IEEE S&P 2016)"
     "Keeping Authorities 'Honest or Bust' with Decentralized Witness Cosigning & Split-View Fraud Proofs.")
    ("Deterministic Engineering (10.156 / 10.166)"
     "Asymmetric Ed25519 Signed Tree Heads eliminating the trusted-coordinator assumption."))
  quint-module: "transparency_log_equivocation"
  quint-file: "TransparencyLogEquivocation.qnt"
  domain-dir: "engineering/defense/transparency-log-equivocation"
  verify-depth: 10
  countermodel-depth: 6
  rules:
  '((transparency-log-safe DE-TLOG-SAFE quint)
    (transparency-log-countermodel DE-TLOG-COUNTER quint))
  dependencies:
  '((DE-TLOG-SAFE source)
    (DE-TLOG-SAFE profile)
    (DE-TLOG-SAFE method)
    (DE-TLOG-COUNTER source)
    (DE-TLOG-COUNTER profile)
    (DE-TLOG-COUNTER method))
  invariant: "No governance audit accepts an unverified entry (unverifiedEntryAccepts == 0), a retroactively rewritten or rolled-back history (historyRewriteAccepts == 0), or a split-view equivocating coordinator (equivocationAccepts == 0)."
  parameters: '()
  state:
  '((sth1Published "bool" "false")
    (sth2Published "bool" "false")
    (inclusionProofValid "bool" "false")
    (consistencyProofValid "bool" "false")
    (equivocationDetected "bool" "false")
    (unverifiedEntryAccepts "int" "0")
    (historyRewriteAccepts "int" "0")
    (equivocationAccepts "int" "0")
    (verifiedAudits "int" "0"))
  guards:
  '((require-inclusion-proof (. h inclusionProofValid))
    (require-append-only-consistency (. h consistencyProofValid))
    (forbid-split-view-equivocation (not (. h equivocationDetected))))
  transitions:
  '((publishInitialSth
      (action publishInitialSth ()
        (if (not (. h sth1Published))
          (set-h (sth1Published #t))
          (keep-h))))
    (verifyEntryInclusion
      (action verifyEntryInclusion ()
        (if (and (. h sth1Published) (not (. h inclusionProofValid)))
          (set-h (inclusionProofValid #t))
          (keep-h))))
    (appendConsistentSth2
      (action appendConsistentSth2 ()
        (if (and (. h sth1Published) (not (. h sth2Published)))
          (set-h (sth2Published #t) (consistencyProofValid #t))
          (keep-h))))
    (attemptHistoryRewrite
      (action attemptHistoryRewrite ()
        (if (and (. h sth1Published) (not (. h sth2Published)))
          (set-h (sth2Published #t) (consistencyProofValid #f))
          (keep-h))))
    (emitSplitViewSth
      (action emitSplitViewSth ()
        (if (and (. h sth1Published) (not (. h equivocationDetected)))
          (set-h (equivocationDetected #t))
          (keep-h))))
    (acceptAuditSnapshot
      (action acceptAuditSnapshot ()
        (if (and (. h sth2Published)
                 (guard require-inclusion-proof (. h inclusionProofValid))
                 (guard require-append-only-consistency (. h consistencyProofValid))
                 (guard forbid-split-view-equivocation (not (. h equivocationDetected))))
          (set-h (verifiedAudits (+ (. h verifiedAudits) 1))
                 (unverifiedEntryAccepts
                   (if (. h inclusionProofValid)
                     (. h unverifiedEntryAccepts)
                     (+ (. h unverifiedEntryAccepts) 1)))
                 (historyRewriteAccepts
                   (if (. h consistencyProofValid)
                     (. h historyRewriteAccepts)
                     (+ (. h historyRewriteAccepts) 1)))
                 (equivocationAccepts
                   (if (not (. h equivocationDetected))
                     (. h equivocationAccepts)
                     (+ (. h equivocationAccepts) 1))))
          (keep-h))))
    (step
      (action step ()
        (any publishInitialSth verifyEntryInclusion appendConsistentSth2
             attemptHistoryRewrite emitSplitViewSth acceptAuditSnapshot))))
  safety:
  '(and (= (. h unverifiedEntryAccepts) 0)
        (= (. h historyRewriteAccepts) 0)
        (= (. h equivocationAccepts) 0))
  traces:
  '((verifiedAppendOnlyAuditSafeTest
      (run verifiedAppendOnlyAuditSafeTest
        (then init publishInitialSth verifyEntryInclusion appendConsistentSth2 acceptAuditSnapshot
              (all (assert safety)
                   (assert (= (. h verifiedAudits) 1))
                   (keep-h)))))
    (unverifiedInclusionViolatesSafetyTest
      (run unverifiedInclusionViolatesSafetyTest
        (then init publishInitialSth appendConsistentSth2 acceptUnverifiedInclusion
              (all (assert (not safety))
                   (assert (> (. h unverifiedEntryAccepts) 0))
                   (keep-h)))))
    (historyRewriteViolatesSafetyTest
      (run historyRewriteViolatesSafetyTest
        (then init publishInitialSth verifyEntryInclusion attemptHistoryRewrite acceptRewrittenHistory
              (all (assert (not safety))
                   (assert (> (. h historyRewriteAccepts) 0))
                   (keep-h)))))
    (splitViewViolatesSafetyTest
      (run splitViewViolatesSafetyTest
        (then init publishInitialSth verifyEntryInclusion appendConsistentSth2 emitSplitViewSth acceptSplitView
              (all (assert (not safety))
                   (assert (> (. h equivocationAccepts) 0))
                   (keep-h))))))
  countermodels:
  (list UnverifiedInclusionCountermodel
        HistoryRewriteCountermodel
        SplitViewEquivocationCountermodel)
  limits: "Finite two-STH inclusion, consistency, and witness-gossip equivocation abstraction; does not model network eclipse attacks that completely isolate all external witnesses from gossiping with one another.")

(.def (UnverifiedInclusionCountermodel @ TransparencyLogEquivocationModel)
  identity: 'engineering.defense.transparency-log-equivocation.unverified-inclusion
  dropped-guard: 'require-inclusion-proof
  step-action: "stepUnverifiedInclusion"
  derive-from-transition: 'acceptAuditSnapshot
  derive-action-name: 'acceptUnverifiedInclusion
  expected-itf-predicate: "h.unverifiedEntryAccepts > 0")

(.def (HistoryRewriteCountermodel @ TransparencyLogEquivocationModel)
  identity: 'engineering.defense.transparency-log-equivocation.history-rewrite
  dropped-guard: 'require-append-only-consistency
  step-action: "stepHistoryRewrite"
  derive-from-transition: 'acceptAuditSnapshot
  derive-action-name: 'acceptRewrittenHistory
  expected-itf-predicate: "h.historyRewriteAccepts > 0")

(.def (SplitViewEquivocationCountermodel @ TransparencyLogEquivocationModel)
  identity: 'engineering.defense.transparency-log-equivocation.split-view
  dropped-guard: 'forbid-split-view-equivocation
  step-action: "stepSplitView"
  derive-from-transition: 'acceptAuditSnapshot
  derive-action-name: 'acceptSplitView
  expected-itf-predicate: "h.equivocationAccepts > 0")
