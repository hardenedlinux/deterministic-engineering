;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Durable AI (10.157): Role-Projected Context (Truth vs View), Compaction-Loss-Free
;;; Evidence Offloading (Anti-Overthinking), Multi-Agent ReadSet x WriteSet SSI Write-Skew
;;; Prevention, and Monotonic M3 Lease Fencing for Stalled Workers.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export DurableAiContextSsiModel
        SemanticWriteSkewMergeCountermodel
        ZombieWorkerFenceCountermodel
        UnsanitizedContextInjectionCountermodel)

(.def (DurableAiContextSsiModel @ ThreatModel.)
  identity: 'engineering.defense.durable-ai-context-ssi
  family: 'engineering.defense.durable-ai-context-ssi
  title: "Durable AI Role-Projected Context & Multi-Agent SSI Write-Skew Governance"
  subdomain: 'quint.engineering.defense
  papers:
  '(("M. J. Cahill, U. Rohm & A. D. Fekete (SIGMOD 2008 / ACM TODS 2009)"
     "Serializable Isolation for Snapshot Databases: rw-antidependency detection against Write-Skew.")
    ("Mighty Gerbils (gerbil-persist) & Deterministic Engineering (10.156 / 10.157)"
     "Durable Merkle Evidence State as Truth, Role-Projected Context as Ephemeral Materialized View, and Anti-Overthinking Sufficiency Offloading."))
  quint-module: "durable_ai_context_ssi"
  quint-file: "DurableAiContextSsi.qnt"
  domain-dir: "engineering/defense/durable-ai-context-ssi"
  verify-depth: 10
  countermodel-depth: 6
  rules:
  '((durable-ai-safe DE-DAI-SAFE quint)
    (durable-ai-countermodel DE-DAI-COUNTER quint))
  dependencies:
  '((DE-DAI-SAFE source)
    (DE-DAI-SAFE profile)
    (DE-DAI-SAFE method)
    (DE-DAI-COUNTER source)
    (DE-DAI-COUNTER profile)
    (DE-DAI-COUNTER method))
  invariant: "Durable Merkle evidence survives raw chat compaction (durableEvidenceIntact), no disjoint-file rw-antidependency merges blindly (writeSkewMerges == 0), no stalled worker with outdated fencing epoch commits (fencedCommits == 0), and no reviewer context carries unsanitized coder prose injection (injectedReviews == 0)."
  parameters: '()
  state:
  '((durableEvidenceIntact "bool" "true")
    (rawChatCompacted "bool" "false")
    (readWriteSkew "bool" "false")
    (activeEpoch "int" "1")
    (workerEpoch "int" "1")
    (proseSanitized "bool" "true")
    (writeSkewMerges "int" "0")
    (fencedCommits "int" "0")
    (injectedReviews "int" "0"))
  guards:
  '((forbid-semantic-write-skew-merge (not (. h readWriteSkew)))
    (forbid-stale-fencing-commit (= (. h workerEpoch) (. h activeEpoch)))
    (require-sanitized-reviewer-projection (. h proseSanitized)))
  transitions:
  '((compactRawChatHistory
      (action compactRawChatHistory ()
        (if (not (. h rawChatCompacted))
          (set-h (rawChatCompacted #t))
          (keep-h))))
    (introduceRwAntidependency
      (action introduceRwAntidependency ()
        (if (not (. h readWriteSkew))
          (set-h (readWriteSkew #t))
          (keep-h))))
    (revalidateStaleReader
      (action revalidateStaleReader ()
        (if (. h readWriteSkew)
          (set-h (readWriteSkew #f))
          (keep-h))))
    (advanceLeaseEpochOnTimeout
      (action advanceLeaseEpochOnTimeout ()
        (if (= (. h activeEpoch) 1)
          (set-h (activeEpoch 2))
          (keep-h))))
    (refreshWorkerEpoch
      (action refreshWorkerEpoch ()
        (if (< (. h workerEpoch) (. h activeEpoch))
          (set-h (workerEpoch (. h activeEpoch)))
          (keep-h))))
    (injectCoderProseDraft
      (action injectCoderProseDraft ()
        (if (. h proseSanitized)
          (set-h (proseSanitized #f))
          (keep-h))))
    (projectSanitizedReviewerView
      (action projectSanitizedReviewerView ()
        (if (not (. h proseSanitized))
          (set-h (proseSanitized #t))
          (keep-h))))
    (mergeDisjointAgentBranches
      (action mergeDisjointAgentBranches ()
        (if (guard forbid-semantic-write-skew-merge (not (. h readWriteSkew)))
          (set-h (writeSkewMerges
                   (if (. h readWriteSkew)
                     (+ (. h writeSkewMerges) 1)
                     (. h writeSkewMerges))))
          (keep-h))))
    (commitWorkerBranch
      (action commitWorkerBranch ()
        (if (guard forbid-stale-fencing-commit (= (. h workerEpoch) (. h activeEpoch)))
          (set-h (fencedCommits
                   (if (= (. h workerEpoch) (. h activeEpoch))
                     (. h fencedCommits)
                     (+ (. h fencedCommits) 1))))
          (keep-h))))
    (runReviewerEvaluation
      (action runReviewerEvaluation ()
        (if (guard require-sanitized-reviewer-projection (. h proseSanitized))
          (set-h (injectedReviews
                   (if (. h proseSanitized)
                     (. h injectedReviews)
                     (+ (. h injectedReviews) 1))))
          (keep-h))))
    (step
      (action step ()
        (any compactRawChatHistory introduceRwAntidependency revalidateStaleReader
             advanceLeaseEpochOnTimeout refreshWorkerEpoch injectCoderProseDraft
             projectSanitizedReviewerView mergeDisjointAgentBranches commitWorkerBranch
             runReviewerEvaluation))))
  safety:
  '(and (. h durableEvidenceIntact)
        (= (. h writeSkewMerges) 0)
        (= (. h fencedCommits) 0)
        (= (. h injectedReviews) 0))
  traces:
  '((compactionSsiFenceAndSanitizedViewSafeTest
      (run compactionSsiFenceAndSanitizedViewSafeTest
        (then init compactRawChatHistory introduceRwAntidependency revalidateStaleReader
              mergeDisjointAgentBranches advanceLeaseEpochOnTimeout refreshWorkerEpoch
              commitWorkerBranch injectCoderProseDraft projectSanitizedReviewerView
              runReviewerEvaluation
              (all (assert safety)
                   (assert (. h rawChatCompacted))
                   (assert (. h durableEvidenceIntact))
                   (assert (= (. h workerEpoch) 2))
                   (keep-h)))))
    (writeSkewMergeViolatesSafetyTest
      (run writeSkewMergeViolatesSafetyTest
        (then init introduceRwAntidependency mergeBlindWriteSkew
              (all (assert (not safety))
                   (assert (> (. h writeSkewMerges) 0))
                   (keep-h)))))
    (staleFenceCommitViolatesSafetyTest
      (run staleFenceCommitViolatesSafetyTest
        (then init advanceLeaseEpochOnTimeout commitStaleWorkerEpoch
              (all (assert (not safety))
                   (assert (> (. h fencedCommits) 0))
                   (keep-h)))))
    (unsanitizedInjectionViolatesSafetyTest
      (run unsanitizedInjectionViolatesSafetyTest
        (then init injectCoderProseDraft reviewUnsanitizedContext
              (all (assert (not safety))
                   (assert (> (. h injectedReviews) 0))
                   (keep-h))))))
  countermodels:
  (list SemanticWriteSkewMergeCountermodel
        ZombieWorkerFenceCountermodel
        UnsanitizedContextInjectionCountermodel)
  limits: "Finite two-agent SSI rw-antidependency, two-epoch lease fencing, and reviewer context sanitization abstraction; does not model arbitrary multi-hop transitive dependency graphs or covert steganography inside valid code diffs.")

(.def (SemanticWriteSkewMergeCountermodel @ DurableAiContextSsiModel)
  identity: 'engineering.defense.durable-ai-context-ssi.write-skew
  dropped-guard: 'forbid-semantic-write-skew-merge
  step-action: "stepWriteSkew"
  derive-from-transition: 'mergeDisjointAgentBranches
  derive-action-name: 'mergeBlindWriteSkew
  expected-itf-predicate: "h.writeSkewMerges > 0")

(.def (ZombieWorkerFenceCountermodel @ DurableAiContextSsiModel)
  identity: 'engineering.defense.durable-ai-context-ssi.stale-fence
  dropped-guard: 'forbid-stale-fencing-commit
  step-action: "stepStaleFence"
  derive-from-transition: 'commitWorkerBranch
  derive-action-name: 'commitStaleWorkerEpoch
  expected-itf-predicate: "h.fencedCommits > 0")

(.def (UnsanitizedContextInjectionCountermodel @ DurableAiContextSsiModel)
  identity: 'engineering.defense.durable-ai-context-ssi.unsanitized-review
  dropped-guard: 'require-sanitized-reviewer-projection
  step-action: "stepUnsanitizedReview"
  derive-from-transition: 'runReviewerEvaluation
  derive-action-name: 'reviewUnsanitizedContext
  expected-itf-predicate: "h.injectedReviews > 0")
