;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Streaming LLM & HTTP output budget envelope: pre-allocation chunk cap checks,
;;; cumulative text+thinking byte accounting, SSE/HTTP path symmetry, and
;;; fail-closed buffer release on overflow refusal (SM17).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export StreamingOutputBudgetEnvelopeModel)

(.def (StreamingOutputBudgetEnvelopeModel @ ThreatModel.)
  identity: 'engineering.concurrency.streaming-output-budget-envelope
  family: 'engineering.concurrency.streaming-output-budget-envelope
  title: "Streaming Output Budget, Pre-Allocation Cap & Thinking-Channel Accounting Envelope"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("M. Grottke & K. S. Trivedi (IEEE Computer 2007)"
     "Fighting Bugs: Remove, Retry, Replicate, and Rejuvenate — cumulative output-budget accounting across streaming and aggregation paths prevents unbounded heap exhaustion.")
    ("RFC 9110 / RFC 9112 (IETF 2022)"
     "HTTP Semantics & HTTP/1.1 — Content-Length fail-fast validation and incremental chunked body reads enforce byte caps before allocating full payloads.")
    ("S. A. Crosby & D. S. Wallach (USENIX Security 2003)"
     "Denial of Service via Algorithmic Complexity — unaccounted hidden thinking deltas and check-after-buffering reads enable asymmetric memory exhaustion."))
  quint-module: "concurrency_streaming_output_budget_envelope"
  quint-file: "StreamingOutputBudgetEnvelope.qnt"
  domain-dir: "engineering/concurrency/streaming-output-budget-envelope"
  rules:
  '((conc-sbud-precheck-before-buffer CONC-SBUD-PRECHECK-BEFORE-BUFFER quint)
    (conc-sbud-account-thinking-bytes CONC-SBUD-ACCOUNT-THINKING-BYTES quint)
    (conc-sbud-sse-complete-symmetry CONC-SBUD-SSE-COMPLETE-SYMMETRY quint))
  dependencies:
  '((CONC-SBUD-PRECHECK-BEFORE-BUFFER source)
    (CONC-SBUD-PRECHECK-BEFORE-BUFFER profile)
    (CONC-SBUD-PRECHECK-BEFORE-BUFFER method)
    (CONC-SBUD-ACCOUNT-THINKING-BYTES source)
    (CONC-SBUD-ACCOUNT-THINKING-BYTES profile)
    (CONC-SBUD-ACCOUNT-THINKING-BYTES method)
    (CONC-SBUD-SSE-COMPLETE-SYMMETRY source)
    (CONC-SBUD-SSE-COMPLETE-SYMMETRY profile)
    (CONC-SBUD-SSE-COMPLETE-SYMMETRY method))
  invariant: "Every incremental stream and HTTP/SSE aggregation path checks textBytes + thinkingBytes + delta <= budgetLimit before buffering, accounts hidden thinking deltas in the same cumulative budget, enforces peakRetainedBytes <= budgetLimit (no check-after-buffering spike), and releases buffered state immediately upon completion or overflow refusal."
  limits: "Finite 4-unit cumulative byte-budget abstraction; verifies pre-allocation chunk cap checks, unified text+thinking budget accounting, SSE completion path parity, and buffer release on refusal/completion, not TCP windowing or TLS record framing.")
