;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Metamorphic search query algebra, qualifier orthogonality, scope-replace
;;; determinism & clipped tab hit-test fidelity model (SM10).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export SearchQueryMetamorphicAlgebraModel
        QualifierLeakCountermodel
        StaleScopeShadowCountermodel
        ClippedTabPhantomHitCountermodel)

(.def (SearchQueryMetamorphicAlgebraModel @ ThreatModel.)
  identity: 'engineering.concurrency.search-query-metamorphic-algebra
  family: 'engineering.concurrency.search-query-metamorphic-algebra
  title: "Search Query Metamorphic Algebra, Scope Replacement & Viewport Hit-Test Fidelity"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("Z. Q. Zhou, S. Xiang & T. Y. Chen (IEEE TSE 2016)"
     "Metamorphic Testing for Software Quality Assessment: A Study of Search Engines — relational oracles for search queries.")
    ("T. Y. Chen, F.-C. Kuo, H. Liu, P.-L. Poon, D. Towey, T. H. Tse & Z. Q. Zhou (ACM CSUR 2018)"
     "Metamorphic Testing: A Review of Challenges and Opportunities — monotonicity and invariance properties.")
    ("L. Lampropoulos, M. Hicks & B. C. Pierce (ACM OOPSLA 2019)"
     "Coverage Guided, Property Based Testing (FuzzChick) — combining property oracles with fuzzing feedback.")
    ("H. Goldstein, J. W. Cutler, D. Dickstein, B. C. Pierce & A. Head (IEEE/ACM ICSE 2024)"
     "Property-Based Testing in Practice — stateful and metamorphic properties in production software."))
  quint-module: "concurrency_search_query_metamorphic_algebra"
  quint-file: "SearchQueryMetamorphicAlgebra.qnt"
  domain-dir: "engineering/concurrency/search-query-metamorphic-algebra"
  quint-imports: '()
  rules:
  '((conc-search-qual-ortho CONC-SEARCH-QUAL-ORTHO quint)
    (conc-search-scope-replace CONC-SEARCH-SCOPE-REPLACE quint)
    (conc-search-tab-clip CONC-SEARCH-TAB-CLIP quint))
  dependencies:
  '((CONC-SEARCH-QUAL-ORTHO source)
    (CONC-SEARCH-QUAL-ORTHO profile)
    (CONC-SEARCH-QUAL-ORTHO method)
    (CONC-SEARCH-SCOPE-REPLACE source)
    (CONC-SEARCH-SCOPE-REPLACE profile)
    (CONC-SEARCH-SCOPE-REPLACE method)
    (CONC-SEARCH-TAB-CLIP source)
    (CONC-SEARCH-TAB-CLIP profile)
    (CONC-SEARCH-TAB-CLIP method))
  invariant: "Axis qualifiers never leak into literal text matching, interactive scoping replaces any conflicting prior axis rather than being shadowed by last-wins parsing, negation shrinks match sets monotonically, and clipped tabs never register phantom hits."
  parameters: '()
  state:
  '((hasQualifier "bool" "false")
    (hasNegation "bool" "false")
    (activeScopeEpoch "int" "0")
    (effectiveScopeEpoch "int" "0")
    (matchedCount "int" "2")
    (clippedClicksIgnored "int" "0")
    (qualifierLeaked "bool" "false")
    (phantomTabHit "bool" "false"))
  guards:
  '((strip-qualifier-from-text-match false)
    (replace-prior-scope-axis true)
    (clip-tab-hit-test-to-viewport false))
  transitions:
  '((applyQualifier
      (action applyQualifier ()
        (if (not (. h hasQualifier))
          (set-h (hasQualifier true)
                 (qualifierLeaked (guard strip-qualifier-from-text-match false true))
                 (matchedCount (if (guard strip-qualifier-from-text-match false true) 0 (. h matchedCount))))
          (keep-h))))
    (applyScopeReplace
      (action applyScopeReplace ()
        (if (< (. h activeScopeEpoch) 2)
          (set-h (activeScopeEpoch (+ (. h activeScopeEpoch) 1))
                 (effectiveScopeEpoch
                   (if (guard replace-prior-scope-axis true false)
                     (+ (. h activeScopeEpoch) 1)
                     (if (> (. h effectiveScopeEpoch) 0)
                       (. h effectiveScopeEpoch)
                       (+ (. h activeScopeEpoch) 1)))))
          (keep-h))))
    (addNegationFilter
      (action addNegationFilter ()
        (if (and (not (. h hasNegation)) (> (. h matchedCount) 0))
          (set-h (hasNegation true)
                 (matchedCount (- (. h matchedCount) 1)))
          (keep-h))))
    (clickClippedTab
      (action clickClippedTab ()
        (if (< (. h clippedClicksIgnored) 2)
          (set-h (clippedClicksIgnored (+ (. h clippedClicksIgnored) 1))
                 (phantomTabHit (guard clip-tab-hit-test-to-viewport false true)))
          (keep-h))))
    (resetQuery
      (action resetQuery ()
        (if (or (. h hasQualifier) (. h hasNegation) (> (. h activeScopeEpoch) 0))
          (set-h (hasQualifier false)
                 (hasNegation false)
                 (activeScopeEpoch 0)
                 (effectiveScopeEpoch 0)
                 (matchedCount 2))
          (keep-h))))
    (step
      (action step ()
        (any applyQualifier applyScopeReplace addNegationFilter clickClippedTab resetQuery))))
  safety:
  '(and (not (. h qualifierLeaked))
        (= (. h effectiveScopeEpoch) (. h activeScopeEpoch))
        (not (. h phantomTabHit))
        (<= (. h matchedCount) 2))
  traces:
  '((checkMetamorphicSafe
      (action checkMetamorphicSafe ()
        (all (assert (not (. h qualifierLeaked)))
             (assert (= (. h effectiveScopeEpoch) (. h activeScopeEpoch)))
             (assert (not (. h phantomTabHit)))
             (assert (> (. h clippedClicksIgnored) 0))
             (assert safety)
             (keep-h))))
    (checkMetamorphicViolation
      (action checkMetamorphicViolation ()
        (all (assert (or (. h qualifierLeaked)
                         (not (= (. h effectiveScopeEpoch) (. h activeScopeEpoch)))
                         (. h phantomTabHit)))
             (assert (not safety))
             (keep-h))))
    (metamorphicLifecycleTest
      (run metamorphicLifecycleTest
        (then init applyQualifier applyScopeReplace applyScopeReplace addNegationFilter clickClippedTab resetQuery checkMetamorphicSafe)))
    (qualifierLeakRefutedTest
      (run qualifierLeakRefutedTest
        (then init applyQualifierLeaked checkMetamorphicViolation)))
    (staleScopeShadowRefutedTest
      (run staleScopeShadowRefutedTest
        (then init applyScopeReplace applyScopePrependShadowed checkMetamorphicViolation)))
    (clippedTabPhantomRefutedTest
      (run clippedTabPhantomRefutedTest
        (then init clickClippedTabPhantom checkMetamorphicViolation))))
  countermodels: (list QualifierLeakCountermodel StaleScopeShadowCountermodel ClippedTabPhantomHitCountermodel)
  limits: "Finite metamorphic algebra abstraction over 2-epoch scope replacement, axis qualifiers, negation monotonicity, and clipped viewport hit-tests; concrete UTF-8 case folding and arbitrary query fuzzing are tested via Go testing.F and Rust proptest.")

(.def (QualifierLeakCountermodel @ SearchQueryMetamorphicAlgebraModel)
  identity: 'engineering.concurrency.search-query-metamorphic-algebra.qualifier-leak
  dropped-guard: 'strip-qualifier-from-text-match
  step-action: "stepQualifierLeak"
  derive-from-transition: 'applyQualifier
  derive-action-name: 'applyQualifierLeaked
  expected-itf-predicate: "h.qualifierLeaked == true")

(.def (StaleScopeShadowCountermodel @ SearchQueryMetamorphicAlgebraModel)
  identity: 'engineering.concurrency.search-query-metamorphic-algebra.stale-scope-shadow
  dropped-guard: 'replace-prior-scope-axis
  step-action: "stepStaleScopeShadow"
  derive-from-transition: 'applyScopeReplace
  derive-action-name: 'applyScopePrependShadowed
  expected-itf-predicate: "h.effectiveScopeEpoch != h.activeScopeEpoch")

(.def (ClippedTabPhantomHitCountermodel @ SearchQueryMetamorphicAlgebraModel)
  identity: 'engineering.concurrency.search-query-metamorphic-algebra.clipped-tab-hit
  dropped-guard: 'clip-tab-hit-test-to-viewport
  step-action: "stepClippedTabHit"
  derive-from-transition: 'clickClippedTab
  derive-action-name: 'clickClippedTabPhantom
  expected-itf-predicate: "h.phantomTabHit == true")
