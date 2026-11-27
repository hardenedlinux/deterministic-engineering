;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Bounded UI DOM viewport window & O(1) incremental frame-budget render model (SM7).
;;; Co-located Yuanxu unit: single source of truth alongside UiRenderWindowBudget.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export UiRenderWindowBudgetModel
        UnboundedDomGrowthCountermodel
        FullReparseFrameStallCountermodel)

(.def (UiRenderWindowBudgetModel @ ThreatModel.)
  identity: 'engineering.concurrency.ui-render-window-budget
  family: 'engineering.concurrency.ui-render-window-budget
  title: "Bounded UI Viewport Window & Incremental Frame-Budget Rendering"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("J. Dean & L. A. Barroso (CACM 2013)"
     "The Tail at Scale — keeping per-request/per-frame work independent of cumulative history length.")
    ("M. Jump & K. S. McKinley (ACM POPL 2007)"
     "Cork — preventing monotonic heap/DOM retention growth across long-lived interactive sessions.")
    ("Web Performance Working Group — RAIL / 120Hz Frame Budget (W3C)"
     "Bounding per-frame layout, parsing, and DOM mutation work below 8.33ms via incremental updates and viewport virtualization."))
  quint-module: "concurrency_ui_render_window"
  quint-file: "UiRenderWindowBudget.qnt"
  domain-dir: "engineering/concurrency/ui-render-window-budget"
  quint-imports: '()
  rules:
  '((conc-dom-window CONC-DOM-WINDOW quint)
    (conc-inc-render CONC-INC-RENDER quint))
  dependencies:
  '((CONC-DOM-WINDOW source)
    (CONC-DOM-WINDOW profile)
    (CONC-DOM-WINDOW method)
    (CONC-INC-RENDER source)
    (CONC-INC-RENDER profile)
    (CONC-INC-RENDER method))
  invariant: "Mounted UI DOM nodes stay within the bounded viewport window regardless of total transcript length, pending animation frames coalesce to at most one, and per-frame incremental work never exceeds the 120Hz frame budget."
  parameters: '()
  state:
  '((totalTurns "int" "0")
    (mountedNodes "int" "0")
    (pendingRafs "int" "0")
    (frameWorkUnits "int" "0"))
  guards:
  '((dom-window-cap (< (. h mountedNodes) 3))
    (incremental-block-render 1))
  transitions:
  '((appendTurnDelta
      (action appendTurnDelta ()
        (if (< (. h totalTurns) 6)
          (set-h (totalTurns (+ (. h totalTurns) 1))
                 (mountedNodes (if (guard dom-window-cap (< (. h mountedNodes) 3))
                                 (+ (. h mountedNodes) 1)
                                 (. h mountedNodes)))
                 (pendingRafs 1))
          (keep-h))))
    (flushFrame
      (action flushFrame ()
        (if (> (. h pendingRafs) 0)
          (set-h (pendingRafs 0)
                 (frameWorkUnits (guard incremental-block-render 1 (. h totalTurns))))
          (keep-h))))
    (switchSessionReset
      (action switchSessionReset ()
        (if (and (> (. h totalTurns) 0) (= (. h pendingRafs) 0))
          (set-h (mountedNodes (if (> (. h totalTurns) 3) 3 (. h totalTurns)))
                 (pendingRafs 1)
                 (frameWorkUnits 0))
          (keep-h))))
    (step
      (action step ()
        (any appendTurnDelta flushFrame switchSessionReset))))
  safety:
  '(and (<= (. h mountedNodes) 3)
        (<= (. h pendingRafs) 1)
        (<= (. h frameWorkUnits) 2))
  traces:
  '((checkSteadyUiFrame
      (action checkSteadyUiFrame ()
        (all (assert (<= (. h mountedNodes) 3))
             (assert (<= (. h pendingRafs) 1))
             (assert (<= (. h frameWorkUnits) 2))
             (assert (> (. h totalTurns) 3))
             (assert safety)
             (keep-h))))
    (checkUiRenderViolation
      (action checkUiRenderViolation ()
        (all (assert (or (> (. h mountedNodes) 3) (> (. h frameWorkUnits) 2)))
             (assert (not safety))
             (keep-h))))
    (windowedIncrementalRenderTest
      (run windowedIncrementalRenderTest
        (then init appendTurnDelta appendTurnDelta appendTurnDelta appendTurnDelta flushFrame switchSessionReset flushFrame checkSteadyUiFrame)))
    (unboundedDomGrowthRefutedTest
      (run unboundedDomGrowthRefutedTest
        (then init appendTurnDelta appendTurnDelta appendTurnDelta appendTurnDeltaUnbounded checkUiRenderViolation)))
    (fullReparseStallRefutedTest
      (run fullReparseStallRefutedTest
        (then init appendTurnDelta appendTurnDelta appendTurnDelta flushFrameFullReparse checkUiRenderViolation))))
  countermodels: (list UnboundedDomGrowthCountermodel FullReparseFrameStallCountermodel)
  limits: "Finite 3-node viewport window and 2-unit frame-budget abstraction; models DOM virtualization, rAF coalescing, and O(1) incremental rendering vs. O(N) full re-parse, not browser CSS layout engines or GPU compositor shaders.")

(.def (UnboundedDomGrowthCountermodel @ UiRenderWindowBudgetModel)
  identity: 'engineering.concurrency.ui-render-window-budget.unbounded-dom-growth
  dropped-guard: 'dom-window-cap
  step-action: "stepUnboundedDomGrowth"
  derive-from-transition: 'appendTurnDelta
  derive-action-name: 'appendTurnDeltaUnbounded
  expected-itf-predicate: "h.mountedNodes > 3")

(.def (FullReparseFrameStallCountermodel @ UiRenderWindowBudgetModel)
  identity: 'engineering.concurrency.ui-render-window-budget.full-reparse-stall
  dropped-guard: 'incremental-block-render
  step-action: "stepFullReparseStall"
  derive-from-transition: 'flushFrame
  derive-action-name: 'flushFrameFullReparse
  expected-itf-predicate: "h.frameWorkUnits > 2")
