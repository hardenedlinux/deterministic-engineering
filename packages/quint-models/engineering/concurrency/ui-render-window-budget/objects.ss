;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Bounded UI DOM viewport window & O(1) incremental frame-budget render model (SM7).
;;; Co-located Yuanxu unit: single source of truth alongside UiRenderWindowBudget.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export UiRenderWindowBudgetModel)

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
  limits: "Finite 3-node viewport window and 2-unit frame-budget abstraction; models DOM virtualization, rAF coalescing, and O(1) incremental rendering vs. O(N) full re-parse, not browser CSS layout engines or GPU compositor shaders.")
