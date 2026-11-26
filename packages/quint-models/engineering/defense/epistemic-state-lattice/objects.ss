;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; F1: Six-state epistemic and contract lattice (10.153 / 20.16 DE01).
;;; Prevents P1 silent-fallback masking, P1 last-writer-wins conflict erasure,
;;; and P3 collapsing pending/unknown states into established violations.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export EpistemicStateLatticeModel
        FallbackOnDefectCountermodel
        ViolationOnPendingCountermodel
        ConflictLwwCountermodel)

(.def (EpistemicStateLatticeModel @ ThreatModel.)
  identity: 'engineering.defense.epistemic-state-lattice
  family: 'engineering.defense.epistemic-state-lattice
  title: "Six-State Epistemic Lattice & Non-Collapsing Defense Boundaries"
  subdomain: 'quint.engineering.defense
  papers:
  '(("N. D. Belnap (1977)"
     "A Useful Four-Valued Logic: separating Proven, Refuted, Unknown, and Conflict without explosion.")
    ("Deterministic Engineering (20.16 / 10.153)"
     "F1 six-state contract lattice: SetupDefect, PendingMethod, PendingScope, Proven, Refuted, and Conflict."))
  quint-module: "epistemic_state_lattice"
  quint-file: "EpistemicStateLattice.qnt"
  domain-dir: "engineering/defense/epistemic-state-lattice"
  verify-depth: 10
  countermodel-depth: 8
  rules:
  '((epistemic-safe DE-EPI-SAFE quint)
    (epistemic-countermodel DE-EPI-COUNTER quint))
  dependencies:
  '((DE-EPI-SAFE source)
    (DE-EPI-SAFE profile)
    (DE-EPI-SAFE method)
    (DE-EPI-COUNTER source)
    (DE-EPI-COUNTER profile)
    (DE-EPI-COUNTER method))
  invariant: "Missing expected body (SetupDefect), incomplete method/scope (PendingMethod/PendingScope), and unresolved contradictory records (Conflict) never collapse into Proven (3) or Refuted (4)."
  parameters: '()
  state:
  '((bodyPresent "bool" "false")
    (methodDone "bool" "false")
    (scopeKnown "bool" "false")
    (hasAllow "bool" "false")
    (hasDeny "bool" "false")
    (conflictResolved "bool" "false")
    (status "int" "0"))
  guards:
  '((no-fallback-on-defect (. h bodyPresent))
    (no-violation-on-pending (and (. h methodDone) (. h scopeKnown)))
    (preserve-conflict-no-lww (or (not (. h hasDeny)) (. h conflictResolved))))
  transitions:
  '((supplyBody
      (action supplyBody ()
        (if (not (. h bodyPresent))
          (set-h (bodyPresent #t)
                 (status (if (= (. h status) 0) 1 (. h status))))
          (keep-h))))
    (completeMethod
      (action completeMethod ()
        (if (not (. h methodDone))
          (set-h (methodDone #t)
                 (status (if (= (. h status) 1) 2 (. h status))))
          (keep-h))))
    (establishScope
      (action establishScope ()
        (if (not (. h scopeKnown))
          (set-h (scopeKnown #t))
          (keep-h))))
    (recordAllow
      (action recordAllow ()
        (if (not (. h hasAllow))
          (set-h (hasAllow #t)
                 (status (if (. h hasDeny) 5 (. h status))))
          (keep-h))))
    (recordDeny
      (action recordDeny ()
        (if (not (. h hasDeny))
          (set-h (hasDeny #t)
                 (status (if (. h hasAllow) 5 (. h status))))
          (keep-h))))
    (authorizeConflictResolution
      (action authorizeConflictResolution ()
        (if (and (. h hasAllow) (. h hasDeny) (not (. h conflictResolved)))
          (set-h (conflictResolved #t))
          (keep-h))))
    (concludeProven
      (action concludeProven ()
        (if (and (guard no-fallback-on-defect (. h bodyPresent))
                 (. h methodDone)
                 (. h scopeKnown)
                 (. h hasAllow)
                 (guard preserve-conflict-no-lww
                        (or (not (. h hasDeny)) (. h conflictResolved))))
          (set-h (status 3))
          (keep-h))))
    (concludeRefuted
      (action concludeRefuted ()
        (if (and (. h bodyPresent)
                 (guard no-violation-on-pending (and (. h methodDone) (. h scopeKnown)))
                 (. h hasDeny)
                 (or (not (. h hasAllow)) (. h conflictResolved)))
          (set-h (status 4))
          (keep-h))))
    (step
      (action step ()
        (any supplyBody completeMethod establishScope
             recordAllow recordDeny authorizeConflictResolution
             concludeProven concludeRefuted))))
  safety:
  '(and (or (. h bodyPresent) (and (!= (. h status) 3) (!= (. h status) 4)))
        (or (and (. h methodDone) (. h scopeKnown))
            (and (!= (. h status) 3) (!= (. h status) 4)))
        (or (not (and (. h hasAllow) (. h hasDeny)))
            (. h conflictResolved)
            (and (!= (. h status) 3) (!= (. h status) 4))))
  traces:
  '((validProvenTest
      (run validProvenTest
        (then init supplyBody completeMethod establishScope recordAllow concludeProven
              (all (assert safety)
                   (assert (= (. h status) 3))
                   (keep-h)))))
    (conflictPreservedUntilResolvedTest
      (run conflictPreservedUntilResolvedTest
        (then init supplyBody completeMethod establishScope recordAllow recordDeny
              (all (assert safety)
                   (assert (= (. h status) 5))
                   (keep-h))
              authorizeConflictResolution concludeProven
              (all (assert safety)
                   (assert (= (. h status) 3))
                   (keep-h)))))
    (fallbackOnDefectViolatesSafetyTest
      (run fallbackOnDefectViolatesSafetyTest
        (then init completeMethod establishScope recordAllow concludeProvenIgnoreDefect
              (all (assert (not safety))
                   (assert (not (. h bodyPresent)))
                   (assert (= (. h status) 3))
                   (keep-h)))))
    (violationOnPendingViolatesSafetyTest
      (run violationOnPendingViolatesSafetyTest
        (then init supplyBody recordDeny concludeRefutedWhilePending
              (all (assert (not safety))
                   (assert (= (. h status) 4))
                   (keep-h)))))
    (conflictLwwViolatesSafetyTest
      (run conflictLwwViolatesSafetyTest
        (then init supplyBody completeMethod establishScope recordAllow recordDeny concludeProvenLww
              (all (assert (not safety))
                   (assert (. h hasAllow))
                   (assert (. h hasDeny))
                   (assert (not (. h conflictResolved)))
                   (assert (= (. h status) 3))
                   (keep-h))))))
  countermodels:
  (list FallbackOnDefectCountermodel
        ViolationOnPendingCountermodel
        ConflictLwwCountermodel)
  limits: "Finite six-state epistemic abstraction (0=SetupDefect, 1=PendingMethod, 2=PendingScope, 3=Proven, 4=Refuted, 5=Conflict); does not model cryptographic signature verification or external authority transport.")

(.def (FallbackOnDefectCountermodel @ EpistemicStateLatticeModel)
  identity: 'engineering.defense.epistemic-state-lattice.fallback-on-defect
  dropped-guard: 'no-fallback-on-defect
  step-action: "stepFallbackOnDefect"
  derive-from-transition: 'concludeProven
  derive-action-name: 'concludeProvenIgnoreDefect
  expected-itf-predicate: "h.bodyPresent == false and h.status == 3")

(.def (ViolationOnPendingCountermodel @ EpistemicStateLatticeModel)
  identity: 'engineering.defense.epistemic-state-lattice.violation-on-pending
  dropped-guard: 'no-violation-on-pending
  step-action: "stepViolationOnPending"
  derive-from-transition: 'concludeRefuted
  derive-action-name: 'concludeRefutedWhilePending
  expected-itf-predicate: "h.status == 4 and (h.methodDone == false or h.scopeKnown == false)")

(.def (ConflictLwwCountermodel @ EpistemicStateLatticeModel)
  identity: 'engineering.defense.epistemic-state-lattice.conflict-lww
  dropped-guard: 'preserve-conflict-no-lww
  step-action: "stepConflictLww"
  derive-from-transition: 'concludeProven
  derive-action-name: 'concludeProvenLww
  expected-itf-predicate: "h.hasAllow == true and h.hasDeny == true and h.conflictResolved == false and h.status == 3")
