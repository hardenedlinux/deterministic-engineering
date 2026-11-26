;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Business Extension B12 (10.184 / 10.186): Controlled Context Distillation &
;;; Epistemic Provenance Preservation.
;;; Proves three context-compaction safety invariants:
;;;   1. Anti-Amnesia: every pinned M1 negative constraint/veto is retained
;;;      verbatim during distillation (amnesiaViolations == 0).
;;;   2. Anti-Integrity-Laundering: untrusted external inputs cannot be elevated
;;;      to trusted integrity during summarization (launderingViolations == 0).
;;;   3. Anti-Secrecy-Stripping: paraphrasing never strips DIFC secrecy tags
;;;      without an audited M3 declassification (secrecyStripViolations == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export ContextDistillationProvenanceModel
        PinnedAmnesiaCountermodel
        IntegrityLaunderingCountermodel
        SecrecyStripCountermodel)

(.def (ContextDistillationProvenanceModel @ ThreatModel.)
  identity: 'engineering.defense.context-distillation-provenance
  family: 'engineering.defense.context-distillation-provenance
  title: "Controlled Context Distillation & Epistemic Provenance Preservation"
  subdomain: 'quint.engineering.defense
  papers:
  '(("E. Debenedetti et al. (2025)"
     "CaMeL: Defeating Prompt Injections by Design — monotonic integrity lattice across LLM synthesis.")
    ("A. C. Myers & B. Liskov (SOSP 1997 / ACM TOSEM 2000)"
     "Decentralized Information Flow Control (DIFC) — no silent secrecy tag removal without declassification.")
    ("Deterministic Engineering (10.184 / 10.186)"
     "Anti-amnesia M1 constraint retention, grounded citations, and provenance-preserving context compaction."))
  quint-module: "context_distillation_provenance"
  quint-file: "ContextDistillationProvenance.qnt"
  domain-dir: "engineering/defense/context-distillation-provenance"
  verify-depth: 10
  countermodel-depth: 6
  rules:
  '((context-distillation-safe DE-CDP-SAFE quint)
    (context-distillation-countermodel DE-CDP-COUNTER quint))
  dependencies:
  '((DE-CDP-SAFE source)
    (DE-CDP-SAFE profile)
    (DE-CDP-SAFE method)
    (DE-CDP-COUNTER source)
    (DE-CDP-COUNTER profile)
    (DE-CDP-COUNTER method))
  invariant: "Context distillation retains all pinned M1 constraints (amnesiaViolations == 0), never elevates untrusted external integrity (launderingViolations == 0), and preserves all secret tags without M3 declassification (secrecyStripViolations == 0)."
  parameters: '()
  state:
  '((hasPinnedConstraint "bool" "false")
    (hasUntrustedInput "bool" "false")
    (hasSecretTag "bool" "false")
    (pinnedRetained "bool" "false")
    (outputMarkedUntrusted "bool" "false")
    (secretPreserved "bool" "false")
    (safeDistillations "int" "0")
    (amnesiaViolations "int" "0")
    (launderingViolations "int" "0")
    (secrecyStripViolations "int" "0"))
  guards:
  '((require-pinned-retained (or (not (. h hasPinnedConstraint)) (. h pinnedRetained)))
    (require-integrity-meet (or (not (. h hasUntrustedInput)) (. h outputMarkedUntrusted)))
    (require-secrecy-preserved (or (not (. h hasSecretTag)) (. h secretPreserved))))
  transitions:
  '((ingestPinnedConstraint
      (action ingestPinnedConstraint ()
        (if (not (. h hasPinnedConstraint))
          (set-h (hasPinnedConstraint #t))
          (keep-h))))
    (ingestUntrustedSnippet
      (action ingestUntrustedSnippet ()
        (if (not (. h hasUntrustedInput))
          (set-h (hasUntrustedInput #t))
          (keep-h))))
    (ingestSecretFact
      (action ingestSecretFact ()
        (if (not (. h hasSecretTag))
          (set-h (hasSecretTag #t))
          (keep-h))))
    (copyPinnedIntoSummary
      (action copyPinnedIntoSummary ()
        (if (and (. h hasPinnedConstraint) (not (. h pinnedRetained)))
          (set-h (pinnedRetained #t))
          (keep-h))))
    (tagSummaryUntrusted
      (action tagSummaryUntrusted ()
        (if (and (. h hasUntrustedInput) (not (. h outputMarkedUntrusted)))
          (set-h (outputMarkedUntrusted #t))
          (keep-h))))
    (propagateSecretTag
      (action propagateSecretTag ()
        (if (and (. h hasSecretTag) (not (. h secretPreserved)))
          (set-h (secretPreserved #t))
          (keep-h))))
    (commitDistillation
      (action commitDistillation ()
        (if (and (< (. h safeDistillations) 2)
                 (guard require-pinned-retained (or (not (. h hasPinnedConstraint)) (. h pinnedRetained)))
                 (guard require-integrity-meet (or (not (. h hasUntrustedInput)) (. h outputMarkedUntrusted)))
                 (guard require-secrecy-preserved (or (not (. h hasSecretTag)) (. h secretPreserved))))
          (set-h (safeDistillations (+ (. h safeDistillations) 1))
                 (amnesiaViolations
                   (if (or (not (. h hasPinnedConstraint)) (. h pinnedRetained))
                     (. h amnesiaViolations)
                     (+ (. h amnesiaViolations) 1)))
                 (launderingViolations
                   (if (or (not (. h hasUntrustedInput)) (. h outputMarkedUntrusted))
                     (. h launderingViolations)
                     (+ (. h launderingViolations) 1)))
                 (secrecyStripViolations
                   (if (or (not (. h hasSecretTag)) (. h secretPreserved))
                     (. h secrecyStripViolations)
                     (+ (. h secrecyStripViolations) 1))))
          (keep-h))))
    (step
      (action step ()
        (any ingestPinnedConstraint ingestUntrustedSnippet ingestSecretFact
             copyPinnedIntoSummary tagSummaryUntrusted propagateSecretTag commitDistillation))))
  safety:
  '(and (= (. h amnesiaViolations) 0)
        (= (. h launderingViolations) 0)
        (= (. h secrecyStripViolations) 0))
  traces:
  '((cleanDistillationTest
      (run cleanDistillationTest
        (then init ingestPinnedConstraint ingestUntrustedSnippet ingestSecretFact
              copyPinnedIntoSummary tagSummaryUntrusted propagateSecretTag commitDistillation
              (all (assert safety)
                   (assert (= (. h safeDistillations) 1))
                   (keep-h)))))
    (pinnedAmnesiaViolatesSafetyTest
      (run pinnedAmnesiaViolatesSafetyTest
        (then init ingestPinnedConstraint commitDistillationAmnesia
              (all (assert (not safety))
                   (assert (> (. h amnesiaViolations) 0))
                   (keep-h)))))
    (integrityLaunderingViolatesSafetyTest
      (run integrityLaunderingViolatesSafetyTest
        (then init ingestUntrustedSnippet commitDistillationLaundering
              (all (assert (not safety))
                   (assert (> (. h launderingViolations) 0))
                   (keep-h)))))
    (secrecyStripViolatesSafetyTest
      (run secrecyStripViolatesSafetyTest
        (then init ingestSecretFact commitDistillationSecrecyStrip
              (all (assert (not safety))
                   (assert (> (. h secrecyStripViolations) 0))
                   (keep-h))))))
  countermodels:
  (list PinnedAmnesiaCountermodel
        IntegrityLaunderingCountermodel
        SecrecyStripCountermodel)
  limits: "Bounded 2-distillation abstraction over pinned constraint retention, integrity meet, and secrecy propagation; unbounded multi-item DAG and citation grounding are proved in ContextDistillationAndProvenance.lean.")

(.def (PinnedAmnesiaCountermodel @ ContextDistillationProvenanceModel)
  identity: 'engineering.defense.context-distillation-provenance.pinned-amnesia
  dropped-guard: 'require-pinned-retained
  step-action: "stepPinnedAmnesia"
  derive-from-transition: 'commitDistillation
  derive-action-name: 'commitDistillationAmnesia
  expected-itf-predicate: "h.amnesiaViolations > 0")

(.def (IntegrityLaunderingCountermodel @ ContextDistillationProvenanceModel)
  identity: 'engineering.defense.context-distillation-provenance.integrity-laundering
  dropped-guard: 'require-integrity-meet
  step-action: "stepIntegrityLaundering"
  derive-from-transition: 'commitDistillation
  derive-action-name: 'commitDistillationLaundering
  expected-itf-predicate: "h.launderingViolations > 0")

(.def (SecrecyStripCountermodel @ ContextDistillationProvenanceModel)
  identity: 'engineering.defense.context-distillation-provenance.secrecy-strip
  dropped-guard: 'require-secrecy-preserved
  step-action: "stepSecrecyStrip"
  derive-from-transition: 'commitDistillation
  derive-action-name: 'commitDistillationSecrecyStrip
  expected-itf-predicate: "h.secrecyStripViolations > 0")
