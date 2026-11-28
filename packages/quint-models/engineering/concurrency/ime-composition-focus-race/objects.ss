;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Interactive search-box CJK/IME composition, focus/blur cancellation,
;;; and global keyboard-shortcut isolation model (SM13).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export ImeCompositionFocusRaceModel)

(.def (ImeCompositionFocusRaceModel @ ThreatModel.)
  identity: 'engineering.concurrency.ime-composition-focus-race
  family: 'engineering.concurrency.ime-composition-focus-race
  title: "IME Composition Gate, Blur Preedit Cancellation & Shortcut Isolation"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("W3C UI Events Specification (2024)"
     "Composition Events & KeyboardEvent.isComposing — Enter and shortcuts during active IME composition must not fire application submit or command handlers.")
    ("K. Claessen & J. Hughes (ACM ICFP 2000)"
     "QuickCheck: A Lightweight Tool for Random Testing of Haskell Programs — stateful UI event-interleaving property testing.")
    ("R. Padhye et al. (ACM ISSTA 2019)"
     "Semantic Fuzzing with Zest — structure-aware input mutation uncovering modal UI state-machine bugs."))
  quint-module: "concurrency_ime_composition_focus_race"
  quint-file: "ImeCompositionFocusRace.qnt"
  domain-dir: "engineering/concurrency/ime-composition-focus-race"
  rules:
  '((conc-ime-gate-submit CONC-IME-GATE-SUBMIT quint)
    (conc-ime-blur-cancel CONC-IME-BLUR-CANCEL quint)
    (conc-ime-suppress-shortcut CONC-IME-SUPPRESS-SHORTCUT quint))
  dependencies:
  '((CONC-IME-GATE-SUBMIT source)
    (CONC-IME-GATE-SUBMIT profile)
    (CONC-IME-GATE-SUBMIT method)
    (CONC-IME-BLUR-CANCEL source)
    (CONC-IME-BLUR-CANCEL profile)
    (CONC-IME-BLUR-CANCEL method)
    (CONC-IME-SUPPRESS-SHORTCUT source)
    (CONC-IME-SUPPRESS-SHORTCUT profile)
    (CONC-IME-SUPPRESS-SHORTCUT method))
  invariant: "While an interactive search box is in active IME composition, Enter never triggers premature raw-preedit submission, global shortcuts are suppressed without clobbering candidate selection, and focus loss atomically cancels preedit state leaving zero orphaned compositions."
  limits: "Finite modal IME preedit/focus/shortcut state-machine abstraction; verifies composition gating, blur cleanup, and shortcut suppression, not OS-specific NSTextInputClient or Wayland text-input protocol framing.")
