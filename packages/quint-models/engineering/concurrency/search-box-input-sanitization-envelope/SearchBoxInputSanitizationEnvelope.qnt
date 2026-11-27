// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.search-box-input-sanitization-envelope
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel cap-yank-paste-bytes step=stepPasteCapBypass max-steps=6 itf="h.capBypassCount > 0"
// @countermodel strip-control-chars-on-set step=stepControlCharInjection max-steps=6 itf="h.controlLeakCount > 0"
// @countermodel align-cursor-grapheme-boundary step=stepCursorMidGraphemeSplit max-steps=6 itf="not(h.cursorAligned)"
// Limits: Finite 4-unit byte-cap and cursor-alignment abstraction; verifies uniform cap enforcement across insert/paste/set paths, control-character sanitization, and grapheme boundary alignment, not full Unicode bidi layout or terminal font shaping.
module concurrency_search_box_input_sanitization_envelope {
  type State = { maxBytes: int, inputBytes: int, cursor: int, cursorAligned: bool, editorSynced: bool, capBypassCount: int, controlLeakCount: int, dirtyPasted: bool }
  var h: State
  action init = h' = { maxBytes: 4, inputBytes: 0, cursor: 0, cursorAligned: true, editorSynced: true, capBypassCount: 0, controlLeakCount: 0, dirtyPasted: false }
  action insertCleanChunk = if (h.inputBytes < h.maxBytes) h' = h.with("inputBytes", (h.inputBytes + 1)).with("cursor", (h.inputBytes + 1)).with("cursorAligned", true).with("editorSynced", true) else h' = h
  action pasteLargeYank = if (true) h' = h.with("inputBytes", h.maxBytes).with("cursor", h.maxBytes).with("cursorAligned", true).with("editorSynced", true).with("dirtyPasted", true) else h' = h.with("inputBytes", (h.maxBytes + 4)).with("cursor", (h.maxBytes + 4)).with("capBypassCount", (h.capBypassCount + 1)).with("dirtyPasted", true)
  action setDirtyInput = if (true) h' = h.with("inputBytes", 2).with("cursor", 2).with("cursorAligned", true).with("editorSynced", true) else h' = h.with("inputBytes", 3).with("cursor", 3).with("controlLeakCount", (h.controlLeakCount + 1))
  action moveCursorGrapheme = if (h.cursor > 0) if (true) h' = h.with("cursor", (h.cursor - 1)).with("cursorAligned", true) else h' = h.with("cursor", (h.cursor - 1)).with("cursorAligned", false) else h' = h
  action clearAndReclaim = if (h.inputBytes > 0) h' = h.with("inputBytes", 0).with("cursor", 0).with("cursorAligned", true).with("editorSynced", true) else h' = h
  action step = any { insertCleanChunk, pasteLargeYank, setDirtyInput, moveCursorGrapheme, clearAndReclaim }
  val safety = (h.inputBytes <= h.maxBytes and h.cursor <= h.inputBytes and h.cursor >= 0 and h.cursorAligned and h.editorSynced and h.capBypassCount == 0 and h.controlLeakCount == 0)
  // Countermodel engineering.concurrency.search-box-input-sanitization-envelope.paste-cap-bypass (dropped guard: cap-yank-paste-bytes)
  action pasteLargeYankUncapped = if (false) h' = h.with("inputBytes", h.maxBytes).with("cursor", h.maxBytes).with("cursorAligned", true).with("editorSynced", true).with("dirtyPasted", true) else h' = h.with("inputBytes", (h.maxBytes + 4)).with("cursor", (h.maxBytes + 4)).with("capBypassCount", (h.capBypassCount + 1)).with("dirtyPasted", true)
  action stepPasteCapBypass = any { step, pasteLargeYankUncapped }
  // Countermodel engineering.concurrency.search-box-input-sanitization-envelope.control-char-injection (dropped guard: strip-control-chars-on-set)
  action setDirtyInputUnstripped = if (false) h' = h.with("inputBytes", 2).with("cursor", 2).with("cursorAligned", true).with("editorSynced", true) else h' = h.with("inputBytes", 3).with("cursor", 3).with("controlLeakCount", (h.controlLeakCount + 1))
  action stepControlCharInjection = any { step, setDirtyInputUnstripped }
  // Countermodel engineering.concurrency.search-box-input-sanitization-envelope.cursor-mid-grapheme-split (dropped guard: align-cursor-grapheme-boundary)
  action moveCursorMidGrapheme = if (h.cursor > 0) if (false) h' = h.with("cursor", (h.cursor - 1)).with("cursorAligned", true) else h' = h.with("cursor", (h.cursor - 1)).with("cursorAligned", false) else h' = h
  action stepCursorMidGraphemeSplit = any { step, moveCursorMidGrapheme }
  action checkSanitizationSafe = all { assert(h.dirtyPasted), assert(h.inputBytes <= h.maxBytes), assert(h.cursor <= h.inputBytes), assert(h.cursorAligned), assert(h.editorSynced), assert(h.capBypassCount == 0), assert(h.controlLeakCount == 0), assert(safety), h' = h }
  action checkSanitizationViolated = all { assert((h.inputBytes > h.maxBytes or h.capBypassCount > 0 or h.controlLeakCount > 0 or not(h.cursorAligned))), assert(not(safety)), h' = h }
  run sanitizationEnvelopeSafeTest = init.then(insertCleanChunk).then(pasteLargeYank).then(moveCursorGrapheme).then(setDirtyInput).then(clearAndReclaim).then(checkSanitizationSafe)
  run pasteCapBypassRefutedTest = init.then(pasteLargeYankUncapped).then(checkSanitizationViolated)
  run controlCharInjectionRefutedTest = init.then(setDirtyInputUnstripped).then(checkSanitizationViolated)
  run cursorMidGraphemeRefutedTest = init.then(insertCleanChunk).then(moveCursorMidGrapheme).then(checkSanitizationViolated)
}
