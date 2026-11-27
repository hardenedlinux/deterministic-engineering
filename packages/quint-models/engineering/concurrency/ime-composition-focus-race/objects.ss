;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Interactive search-box CJK/IME composition, focus/blur cancellation,
;;; and global keyboard-shortcut isolation model (SM13).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export ImeCompositionFocusRaceModel
        PrematureEnterSubmitCountermodel
        BlurOrphanPreeditCountermodel
        ShortcutClobbersImeCountermodel)

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
  quint-imports: '()
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
  parameters: '()
  state:
  '((focused "bool" "true")
    (composing "bool" "false")
    (preeditLen "int" "0")
    (committedGen "int" "0")
    (submittedGen "int" "0")
    (prematureSubmits "int" "0")
    (orphanedCompositions "int" "0")
    (shortcutCollisions "int" "0"))
  guards:
  '((gate-submit-during-composition true)
    (cancel-preedit-on-blur true)
    (suppress-shortcut-during-composition true))
  transitions:
  '((focusInput
      (action focusInput ()
        (if (not (. h focused))
          (set-h (focused true))
          (keep-h))))
    (startPreedit
      (action startPreedit ()
        (if (and (. h focused) (< (. h preeditLen) 3))
          (set-h (composing true)
                 (preeditLen (+ (. h preeditLen) 1)))
          (keep-h))))
    (commitComposition
      (action commitComposition ()
        (if (and (. h focused) (. h composing) (< (. h committedGen) 4))
          (set-h (composing false)
                 (preeditLen 0)
                 (committedGen (+ (. h committedGen) 1)))
          (keep-h))))
    (pressEnter
      (action pressEnter ()
        (if (. h focused)
          (if (. h composing)
            (if (guard gate-submit-during-composition true false)
              (keep-h)
              (set-h (prematureSubmits (+ (. h prematureSubmits) 1))))
            (if (< (. h submittedGen) (. h committedGen))
              (set-h (submittedGen (. h committedGen)))
              (keep-h)))
          (keep-h))))
    (blurInput
      (action blurInput ()
        (if (. h focused)
          (if (. h composing)
            (if (guard cancel-preedit-on-blur true false)
              (set-h (focused false)
                     (composing false)
                     (preeditLen 0))
              (set-h (focused false)
                     (orphanedCompositions (+ (. h orphanedCompositions) 1))))
            (set-h (focused false)))
          (keep-h))))
    (pressGlobalShortcut
      (action pressGlobalShortcut ()
        (if (. h focused)
          (if (. h composing)
            (if (guard suppress-shortcut-during-composition true false)
              (keep-h)
              (set-h (shortcutCollisions (+ (. h shortcutCollisions) 1))))
            (keep-h))
          (keep-h))))
    (step
      (action step ()
        (any focusInput startPreedit commitComposition pressEnter blurInput pressGlobalShortcut))))
  safety:
  '(and (= (. h prematureSubmits) 0)
        (= (. h orphanedCompositions) 0)
        (= (. h shortcutCollisions) 0)
        (or (. h focused) (and (not (. h composing)) (= (. h preeditLen) 0)))
        (<= (. h submittedGen) (. h committedGen)))
  traces:
  '((checkImeSafe
      (action checkImeSafe ()
        (all (assert (> (. h submittedGen) 0))
             (assert (= (. h prematureSubmits) 0))
             (assert (= (. h orphanedCompositions) 0))
             (assert (= (. h shortcutCollisions) 0))
             (assert safety)
             (keep-h))))
    (checkImeViolated
      (action checkImeViolated ()
        (all (assert (or (> (. h prematureSubmits) 0)
                         (> (. h orphanedCompositions) 0)
                         (> (. h shortcutCollisions) 0)))
             (assert (not safety))
             (keep-h))))
    (imeCompositionSafeTest
      (run imeCompositionSafeTest
        (then init startPreedit pressEnter pressGlobalShortcut commitComposition pressEnter startPreedit blurInput focusInput checkImeSafe)))
    (prematureEnterRefutedTest
      (run prematureEnterRefutedTest
        (then init startPreedit pressEnterUnguarded checkImeViolated)))
    (blurOrphanRefutedTest
      (run blurOrphanRefutedTest
        (then init startPreedit blurInputOrphan checkImeViolated)))
    (shortcutCollisionRefutedTest
      (run shortcutCollisionRefutedTest
        (then init startPreedit pressGlobalShortcutUnguarded checkImeViolated))))
  countermodels:
  (list PrematureEnterSubmitCountermodel
        BlurOrphanPreeditCountermodel
        ShortcutClobbersImeCountermodel)
  limits: "Finite modal IME preedit/focus/shortcut state-machine abstraction; verifies composition gating, blur cleanup, and shortcut suppression, not OS-specific NSTextInputClient or Wayland text-input protocol framing.")

(.def (PrematureEnterSubmitCountermodel @ ImeCompositionFocusRaceModel)
  identity: 'engineering.concurrency.ime-composition-focus-race.premature-enter-submit
  dropped-guard: 'gate-submit-during-composition
  step-action: "stepPrematureEnterSubmit"
  derive-from-transition: 'pressEnter
  derive-action-name: 'pressEnterUnguarded
  expected-itf-predicate: "h.prematureSubmits > 0")

(.def (BlurOrphanPreeditCountermodel @ ImeCompositionFocusRaceModel)
  identity: 'engineering.concurrency.ime-composition-focus-race.blur-orphan-preedit
  dropped-guard: 'cancel-preedit-on-blur
  step-action: "stepBlurOrphanPreedit"
  derive-from-transition: 'blurInput
  derive-action-name: 'blurInputOrphan
  expected-itf-predicate: "h.orphanedCompositions > 0")

(.def (ShortcutClobbersImeCountermodel @ ImeCompositionFocusRaceModel)
  identity: 'engineering.concurrency.ime-composition-focus-race.shortcut-clobbers-ime
  dropped-guard: 'suppress-shortcut-during-composition
  step-action: "stepShortcutClobbersIme"
  derive-from-transition: 'pressGlobalShortcut
  derive-action-name: 'pressGlobalShortcutUnguarded
  expected-itf-predicate: "h.shortcutCollisions > 0")
