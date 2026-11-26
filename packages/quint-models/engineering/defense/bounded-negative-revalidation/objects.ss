;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; F2: Negative dependencies, immutable frozen cuts, and bounded revalidation (20.16-20.18 DE01 / 10.153).
;;; Proves that expanding a negative domain invalidates only dependent current reviews while
;;; preserving frozen historical snapshots and independent M1 method results, and forbids
;;; re-closing current review by repeating the falsified negative-absence premise.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export BoundedNegativeRevalidationModel
        StaleNegReuseCountermodel
        GlobalHistoryPurgeCountermodel
        PurgeIndependentMethodCountermodel
        RepeatFalseReasonCountermodel)

(.def (BoundedNegativeRevalidationModel @ ThreatModel.)
  identity: 'engineering.defense.bounded-negative-revalidation
  family: 'engineering.defense.bounded-negative-revalidation
  title: "Negative Dependencies, Immutable Cuts & Bounded Revalidation (DE01)"
  subdomain: 'quint.engineering.defense
  papers:
  '(("Deterministic Engineering (20.16 / 20.17 / 20.18)"
     "DE01 / ND / MV / AM: scoped revalidation on negative-dependency changes without global purge or false-reason replay.")
    ("R. Reiter (1980) / Stratified Datalog"
     "Non-monotonic negative dependencies over named finite closed domains."))
  quint-module: "bounded_negative_revalidation"
  quint-file: "BoundedNegativeRevalidation.qnt"
  domain-dir: "engineering/defense/bounded-negative-revalidation"
  verify-depth: 10
  countermodel-depth: 6
  rules:
  '((bounded-reval-safe DE-REVAL-SAFE quint)
    (bounded-reval-countermodel DE-REVAL-COUNTER quint))
  dependencies:
  '((DE-REVAL-SAFE source)
    (DE-REVAL-SAFE profile)
    (DE-REVAL-SAFE method)
    (DE-REVAL-COUNTER source)
    (DE-REVAL-COUNTER profile)
    (DE-REVAL-COUNTER method))
  invariant: "Frozen historical cuts and independent M1 method bytes remain intact across negative-domain expansion; stale negative-absence reviews are invalidated upon relevant counter arrival; re-closing current review requires an admitted replacement reason."
  parameters: '()
  state:
  '((frozenCutIntact "bool" "true")
    (independentMethodValid "bool" "true")
    (negDomainExpanded "bool" "false")
    (oldNegReviewActive "bool" "true")
    (admittedReplacementReason "bool" "false")
    (currentReviewClosed "bool" "true")
    (newCounterReviewed "bool" "false"))
  guards:
  '((invalidate-dependent-review (not (. h negDomainExpanded)))
    (preserve-frozen-history (. h frozenCutIntact))
    (preserve-independent-method (. h independentMethodValid))
    (require-admitted-replacement (. h admittedReplacementReason)))
  transitions:
  '((arriveRelevantCounter
      (action arriveRelevantCounter ()
        (if (not (. h negDomainExpanded))
          (set-h (negDomainExpanded #t)
                 (oldNegReviewActive (guard invalidate-dependent-review #f (. h oldNegReviewActive)))
                 (currentReviewClosed (guard invalidate-dependent-review #f (. h currentReviewClosed)))
                 (frozenCutIntact (guard preserve-frozen-history (. h frozenCutIntact) #f))
                 (independentMethodValid (guard preserve-independent-method (. h independentMethodValid) #f)))
          (keep-h))))
    (supplyReplacementReason
      (action supplyReplacementReason ()
        (if (and (. h negDomainExpanded) (not (. h admittedReplacementReason)))
          (set-h (admittedReplacementReason #t))
          (keep-h))))
    (recloseOldItemReview
      (action recloseOldItemReview ()
        (if (and (. h negDomainExpanded)
                 (not (. h currentReviewClosed))
                 (guard require-admitted-replacement (. h admittedReplacementReason)))
          (set-h (currentReviewClosed #t))
          (keep-h))))
    (reviewNewCounter
      (action reviewNewCounter ()
        (if (and (. h negDomainExpanded) (not (. h newCounterReviewed)))
          (set-h (newCounterReviewed #t))
          (keep-h))))
    (step
      (action step ()
        (any arriveRelevantCounter supplyReplacementReason recloseOldItemReview reviewNewCounter))))
  safety:
  '(and (. h frozenCutIntact)
        (. h independentMethodValid)
        (or (not (. h negDomainExpanded)) (not (. h oldNegReviewActive)))
        (or (not (. h negDomainExpanded))
            (not (. h currentReviewClosed))
            (. h admittedReplacementReason)))
  traces:
  '((boundedRevalidationTest
      (run boundedRevalidationTest
        (then init arriveRelevantCounter
              (all (assert safety)
                   (assert (. h frozenCutIntact))
                   (assert (. h independentMethodValid))
                   (assert (not (. h oldNegReviewActive)))
                   (assert (not (. h currentReviewClosed)))
                   (keep-h))
              supplyReplacementReason recloseOldItemReview reviewNewCounter
              (all (assert safety)
                   (assert (. h currentReviewClosed))
                   (assert (. h newCounterReviewed))
                   (keep-h)))))
    (staleNegReuseCountermodelTest
      (run staleNegReuseCountermodelTest
        (then init arriveCounterKeepStaleReview
              (all (assert (not safety))
                   (assert (. h negDomainExpanded))
                   (assert (. h oldNegReviewActive))
                   (keep-h)))))
    (globalHistoryPurgeCountermodelTest
      (run globalHistoryPurgeCountermodelTest
        (then init arriveCounterPurgeHistory
              (all (assert (not safety))
                   (assert (not (. h frozenCutIntact)))
                   (keep-h)))))
    (purgeMethodCountermodelTest
      (run purgeMethodCountermodelTest
        (then init arriveCounterPurgeMethod
              (all (assert (not safety))
                   (assert (not (. h independentMethodValid)))
                   (keep-h)))))
    (repeatFalseReasonCountermodelTest
      (run repeatFalseReasonCountermodelTest
        (then init arriveRelevantCounter recloseWithoutReplacement
              (all (assert (not safety))
                   (assert (. h currentReviewClosed))
                   (assert (not (. h admittedReplacementReason)))
                   (keep-h))))))
  countermodels:
  (list StaleNegReuseCountermodel
        GlobalHistoryPurgeCountermodel
        PurgeIndependentMethodCountermodel
        RepeatFalseReasonCountermodel)
  limits: "Finite single-counter expansion model of DE01 negative-dependency invalidation; does not model arbitrary multi-domain policy hierarchies or external artifact byte hashing.")

(.def (StaleNegReuseCountermodel @ BoundedNegativeRevalidationModel)
  identity: 'engineering.defense.bounded-negative-revalidation.stale-neg-reuse
  dropped-guard: 'invalidate-dependent-review
  step-action: "stepStaleNegReuse"
  derive-from-transition: 'arriveRelevantCounter
  derive-action-name: 'arriveCounterKeepStaleReview
  expected-itf-predicate: "h.negDomainExpanded == true and h.oldNegReviewActive == true")

(.def (GlobalHistoryPurgeCountermodel @ BoundedNegativeRevalidationModel)
  identity: 'engineering.defense.bounded-negative-revalidation.global-history-purge
  dropped-guard: 'preserve-frozen-history
  step-action: "stepGlobalHistoryPurge"
  derive-from-transition: 'arriveRelevantCounter
  derive-action-name: 'arriveCounterPurgeHistory
  expected-itf-predicate: "h.frozenCutIntact == false")

(.def (PurgeIndependentMethodCountermodel @ BoundedNegativeRevalidationModel)
  identity: 'engineering.defense.bounded-negative-revalidation.purge-independent-method
  dropped-guard: 'preserve-independent-method
  step-action: "stepPurgeIndependentMethod"
  derive-from-transition: 'arriveRelevantCounter
  derive-action-name: 'arriveCounterPurgeMethod
  expected-itf-predicate: "h.independentMethodValid == false")

(.def (RepeatFalseReasonCountermodel @ BoundedNegativeRevalidationModel)
  identity: 'engineering.defense.bounded-negative-revalidation.repeat-false-reason
  dropped-guard: 'require-admitted-replacement
  step-action: "stepRepeatFalseReason"
  derive-from-transition: 'recloseOldItemReview
  derive-action-name: 'recloseWithoutReplacement
  expected-itf-predicate: "h.negDomainExpanded == true and h.currentReviewClosed == true and h.admittedReplacementReason == false")
