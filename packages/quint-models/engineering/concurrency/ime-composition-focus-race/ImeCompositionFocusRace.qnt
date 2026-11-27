// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.ime-composition-focus-race
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel gate-submit-during-composition step=stepPrematureEnterSubmit max-steps=6 itf="h.prematureSubmits > 0"
// @countermodel cancel-preedit-on-blur step=stepBlurOrphanPreedit max-steps=6 itf="h.orphanedCompositions > 0"
// @countermodel suppress-shortcut-during-composition step=stepShortcutClobbersIme max-steps=6 itf="h.shortcutCollisions > 0"
// Limits: Finite modal IME preedit/focus/shortcut state-machine abstraction; verifies composition gating, blur cleanup, and shortcut suppression, not OS-specific NSTextInputClient or Wayland text-input protocol framing.
module concurrency_ime_composition_focus_race {
  type State = { focused: bool, composing: bool, preeditLen: int, committedGen: int, submittedGen: int, prematureSubmits: int, orphanedCompositions: int, shortcutCollisions: int }
  var h: State
  action init = h' = { focused: true, composing: false, preeditLen: 0, committedGen: 0, submittedGen: 0, prematureSubmits: 0, orphanedCompositions: 0, shortcutCollisions: 0 }
  action focusInput = if (not(h.focused)) h' = h.with("focused", true) else h' = h
  action startPreedit = if ((h.focused and h.preeditLen < 3)) h' = h.with("composing", true).with("preeditLen", (h.preeditLen + 1)) else h' = h
  action commitComposition = if ((h.focused and h.composing and h.committedGen < 4)) h' = h.with("composing", false).with("preeditLen", 0).with("committedGen", (h.committedGen + 1)) else h' = h
  action pressEnter = if (h.focused) if (h.composing) if (true) h' = h else h' = h.with("prematureSubmits", (h.prematureSubmits + 1)) else if (h.submittedGen < h.committedGen) h' = h.with("submittedGen", h.committedGen) else h' = h else h' = h
  action blurInput = if (h.focused) if (h.composing) if (true) h' = h.with("focused", false).with("composing", false).with("preeditLen", 0) else h' = h.with("focused", false).with("orphanedCompositions", (h.orphanedCompositions + 1)) else h' = h.with("focused", false) else h' = h
  action pressGlobalShortcut = if (h.focused) if (h.composing) if (true) h' = h else h' = h.with("shortcutCollisions", (h.shortcutCollisions + 1)) else h' = h else h' = h
  action step = any { focusInput, startPreedit, commitComposition, pressEnter, blurInput, pressGlobalShortcut }
  val safety = (h.prematureSubmits == 0 and h.orphanedCompositions == 0 and h.shortcutCollisions == 0 and (h.focused or (not(h.composing) and h.preeditLen == 0)) and h.submittedGen <= h.committedGen)
  // Countermodel engineering.concurrency.ime-composition-focus-race.premature-enter-submit (dropped guard: gate-submit-during-composition)
  action pressEnterUnguarded = if (h.focused) if (h.composing) if (false) h' = h else h' = h.with("prematureSubmits", (h.prematureSubmits + 1)) else if (h.submittedGen < h.committedGen) h' = h.with("submittedGen", h.committedGen) else h' = h else h' = h
  action stepPrematureEnterSubmit = any { step, pressEnterUnguarded }
  // Countermodel engineering.concurrency.ime-composition-focus-race.blur-orphan-preedit (dropped guard: cancel-preedit-on-blur)
  action blurInputOrphan = if (h.focused) if (h.composing) if (false) h' = h.with("focused", false).with("composing", false).with("preeditLen", 0) else h' = h.with("focused", false).with("orphanedCompositions", (h.orphanedCompositions + 1)) else h' = h.with("focused", false) else h' = h
  action stepBlurOrphanPreedit = any { step, blurInputOrphan }
  // Countermodel engineering.concurrency.ime-composition-focus-race.shortcut-clobbers-ime (dropped guard: suppress-shortcut-during-composition)
  action pressGlobalShortcutUnguarded = if (h.focused) if (h.composing) if (false) h' = h else h' = h.with("shortcutCollisions", (h.shortcutCollisions + 1)) else h' = h else h' = h
  action stepShortcutClobbersIme = any { step, pressGlobalShortcutUnguarded }
  action checkImeSafe = all { assert(h.submittedGen > 0), assert(h.prematureSubmits == 0), assert(h.orphanedCompositions == 0), assert(h.shortcutCollisions == 0), assert(safety), h' = h }
  action checkImeViolated = all { assert((h.prematureSubmits > 0 or h.orphanedCompositions > 0 or h.shortcutCollisions > 0)), assert(not(safety)), h' = h }
  run imeCompositionSafeTest = init.then(startPreedit).then(pressEnter).then(pressGlobalShortcut).then(commitComposition).then(pressEnter).then(startPreedit).then(blurInput).then(focusInput).then(checkImeSafe)
  run prematureEnterRefutedTest = init.then(startPreedit).then(pressEnterUnguarded).then(checkImeViolated)
  run blurOrphanRefutedTest = init.then(startPreedit).then(blurInputOrphan).then(checkImeViolated)
  run shortcutCollisionRefutedTest = init.then(startPreedit).then(pressGlobalShortcutUnguarded).then(checkImeViolated)
}
