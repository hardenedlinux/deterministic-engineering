;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; C1-C3 Structured Defensive Programming Anti-Pattern Catalog & Deterministic Replacements.
(import :clan/poo/object
        (only-in :clan/poo/type validate)
        "types.ss")
(export DefensiveAntiPatternCatalog
        DefensiveContrastSubjects
        anti-patterns-by-pathology)

(def DefensiveAntiPatternCatalog
  (map (lambda (entry) (validate AntiPatternEntryType entry))
    (list
      (.o identity: 'c1.silent-fallback-on-defect
          pathology: 'P1-masking
          mutability: 'M1-immutable
          anti-pattern: "Swallowing missing expected body, NULL pointer, or digest mismatch into empty/zero ok fallback."
          deterministic-replacement: "Single trust-boundary parsing returning explicit SetupDefect vs. Refuted status; fail closed without mutating output."
          enforcement-kinds: '(mechanical-type mechanical-formal mechanical-mbt)
          quint-model-ref: 'engineering.defense.epistemic-state-lattice
          contrast-subject-ref: "languages-engineering/c/defense/silent-fallback-contrast")
      (.o identity: 'c1.conflict-last-writer-wins
          pathology: 'P1-masking
          mutability: 'M3-mutable-root
          anti-pattern: "Using last-writer-wins to overwrite contradictory authentic authority records."
          deterministic-replacement: "Preserve competing records as explicit Conflict state until authorized resolution arrives."
          enforcement-kinds: '(mechanical-formal mechanical-mbt semantic-review)
          quint-model-ref: 'engineering.defense.epistemic-state-lattice
          contrast-subject-ref: "languages-engineering/ts/defense/boundary-contrast")
      (.o identity: 'c1.request-time-toctou-authority
          pathology: 'P2-misplaced
          mutability: 'M3-mutable-root
          anti-pattern: "Checking request-time allow or cached grant while skipping live consumption-time revocation check."
          deterministic-replacement: "Bind consumption boundary to live M3 authority/epoch/fencing token witness."
          enforcement-kinds: '(mechanical-formal mechanical-mbt)
          quint-model-ref: 'engineering.defense.unknown-effect-retry
          contrast-subject-ref: "languages-engineering/rust/defense/ownership-boundary-contrast")
      (.o identity: 'c1.blind-retry-unknown-effect
          pathology: 'P2-misplaced
          mutability: 'M3-mutable-root
          anti-pattern: "Auto-retrying a timed-out remote side effect without an explicit idempotency or compensation contract."
          deterministic-replacement: "Preserve PendingUnknownEffect outcome and permit retry strictly when idempotency contract & live use-time authority both hold."
          enforcement-kinds: '(mechanical-formal mechanical-mbt)
          quint-model-ref: 'engineering.defense.unknown-effect-retry
          contrast-subject-ref: "languages-engineering/ts/defense/boundary-contrast")
      (.o identity: 'c1.premature-permit-release
          pathology: 'P2-misplaced
          mutability: 'M3-mutable-root
          anti-pattern: "Releasing capacity/memory permit before payload cleanup completes (wrong RAII drop order or abortable cleanup)."
          deterministic-replacement: "Encode payload-before-permit ownership drop order in Rust struct layout and non-abortable cleanup state."
          enforcement-kinds: '(mechanical-type mechanical-formal mechanical-mbt)
          quint-model-ref: 'engineering.concurrency.backpressure-memory
          contrast-subject-ref: "languages-engineering/rust/defense/ownership-boundary-contrast")
      (.o identity: 'c1.unknown-as-violation
          pathology: 'P3-over-blocking
          mutability: 'M1-immutable
          anti-pattern: "Collapsing PendingScope or PendingMethod into established Refuted violation and blocking unrelated work."
          deterministic-replacement: "Retain explicit PendingScope/PendingMethod state alongside already-established narrower facts."
          enforcement-kinds: '(mechanical-type mechanical-formal)
          quint-model-ref: 'engineering.defense.epistemic-state-lattice
          contrast-subject-ref: "languages-engineering/ts/defense/boundary-contrast")
      (.o identity: 'c1.global-purge-on-negative-change
          pathology: 'P3-over-blocking
          mutability: 'M2-negative-domain
          anti-pattern: "Purging all frozen historical snapshots and independent M1 method caches when one negative dependency changes."
          deterministic-replacement: "Bounded incremental revalidation: invalidate only current uses dependent on the expanded negative domain while preserving frozen cuts and independent results."
          enforcement-kinds: '(mechanical-formal mechanical-mbt)
          quint-model-ref: 'engineering.defense.bounded-negative-revalidation
          contrast-subject-ref: "languages-engineering/ts/defense/boundary-contrast")
      (.o identity: 'c1.redundant-internal-revalidation
          pathology: 'P4-bloat
          mutability: 'M1-immutable
          anti-pattern: "Duplicating trust-boundary validation or style/guard wrappers across internal functions without discharging a new obligation."
          deterministic-replacement: "Parse once into sealed nominal types at the trust boundary; audit guard necessity via F3 countermodel pruning and G1 5-tuple admission."
          enforcement-kinds: '(mechanical-formal semantic-review)))))

(def DefensiveContrastSubjects
  (map (lambda (sub) (validate ContrastSubjectType sub))
    (list
      (.o identity: 'c4.ts.boundary-contrast
          language: 'ts
          relative-dir: "languages-engineering/ts/defense/boundary-contrast"
          pathologies-covered: '(P1-masking P2-misplaced P3-over-blocking)
          verification-tool: "bun test")
      (.o identity: 'c4.c.silent-fallback-contrast
          language: 'c
          relative-dir: "languages-engineering/c/defense/silent-fallback-contrast"
          pathologies-covered: '(P1-masking)
          verification-tool: "clang + cbmc")
      (.o identity: 'c4.cpp.raii-fallback-contrast
          language: 'cpp
          relative-dir: "languages-engineering/cpp/defense/raii-fallback-contrast"
          pathologies-covered: '(P1-masking P2-misplaced)
          verification-tool: "clang++ -std=c++20")
      (.o identity: 'c4.rust.ownership-boundary-contrast
          language: 'rust
          relative-dir: "languages-engineering/rust/defense/ownership-boundary-contrast"
          pathologies-covered: '(P1-masking P2-misplaced)
          verification-tool: "rustc --test"))))

(def (anti-patterns-by-pathology pathology)
  (filter (lambda (entry) (eq? (.get entry pathology) pathology))
          DefensiveAntiPatternCatalog))
