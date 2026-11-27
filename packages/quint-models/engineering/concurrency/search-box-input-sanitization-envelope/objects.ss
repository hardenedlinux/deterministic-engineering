;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Interactive search-box input sanitization, bounded yank/clipboard paste cap,
;;; control-char/ANSI stripping, and grapheme-aligned cursor/sync envelope (SM16).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export SearchBoxInputSanitizationEnvelopeModel
        PasteCapBypassCountermodel
        ControlCharInjectionCountermodel
        CursorMidGraphemeSplitCountermodel)

(.def (SearchBoxInputSanitizationEnvelopeModel @ ThreatModel.)
  identity: 'engineering.concurrency.search-box-input-sanitization-envelope
  family: 'engineering.concurrency.search-box-input-sanitization-envelope
  title: "Search-Box Input Sanitization, Bounded Paste Cap & Grapheme Cursor Envelope"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("K. Claessen & J. Hughes (ACM ICFP 2000)"
     "QuickCheck — stateful property-based testing of text-buffer invariants across arbitrary edit, paste, and undo sequences.")
    ("Unicode Consortium (UAX #29, 2024)"
     "Unicode Text Segmentation — extended grapheme cluster boundaries prevent mid-codepoint and ZWJ cursor corruption.")
    ("R. Padhye et al. (ACM ISSTA 2019)"
     "Semantic Fuzzing with Zest — structure-aware fuzzing exposes cap bypasses and control-sequence leaks across alternate input paths."))
  quint-module: "concurrency_search_box_input_sanitization_envelope"
  quint-file: "SearchBoxInputSanitizationEnvelope.qnt"
  domain-dir: "engineering/concurrency/search-box-input-sanitization-envelope"
  quint-imports: '()
  rules:
  '((conc-sbox-cap-paste-bytes CONC-SBOX-CAP-PASTE-BYTES quint)
    (conc-sbox-strip-controls CONC-SBOX-STRIP-CONTROLS quint)
    (conc-sbox-grapheme-cursor CONC-SBOX-GRAPHEME-CURSOR quint))
  dependencies:
  '((CONC-SBOX-CAP-PASTE-BYTES source)
    (CONC-SBOX-CAP-PASTE-BYTES profile)
    (CONC-SBOX-CAP-PASTE-BYTES method)
    (CONC-SBOX-STRIP-CONTROLS source)
    (CONC-SBOX-STRIP-CONTROLS profile)
    (CONC-SBOX-STRIP-CONTROLS method)
    (CONC-SBOX-GRAPHEME-CURSOR source)
    (CONC-SBOX-GRAPHEME-CURSOR profile)
    (CONC-SBOX-GRAPHEME-CURSOR method))
  invariant: "Every search-box mutation path (insertText, pasteYank, setInput) enforces inputBytes <= maxBytes, strips control/ANSI characters (controlLeakCount == 0), keeps editor and query buffer synchronized on valid grapheme cursor boundaries (cursorAligned == true and cursor <= inputBytes), and reclaims oversized buffer capacity on clear."
  parameters: '()
  state:
  '((maxBytes "int" "4")
    (inputBytes "int" "0")
    (cursor "int" "0")
    (cursorAligned "bool" "true")
    (editorSynced "bool" "true")
    (capBypassCount "int" "0")
    (controlLeakCount "int" "0")
    (dirtyPasted "bool" "false"))
  guards:
  '((cap-yank-paste-bytes true)
    (strip-control-chars-on-set true)
    (align-cursor-grapheme-boundary true))
  transitions:
  '((insertCleanChunk
      (action insertCleanChunk ()
        (if (< (. h inputBytes) (. h maxBytes))
          (set-h (inputBytes (+ (. h inputBytes) 1))
                 (cursor (+ (. h inputBytes) 1))
                 (cursorAligned true)
                 (editorSynced true))
          (keep-h))))
    (pasteLargeYank
      (action pasteLargeYank ()
        (if (guard cap-yank-paste-bytes true false)
          (set-h (inputBytes (. h maxBytes))
                 (cursor (. h maxBytes))
                 (cursorAligned true)
                 (editorSynced true)
                 (dirtyPasted true))
          (set-h (inputBytes (+ (. h maxBytes) 4))
                 (cursor (+ (. h maxBytes) 4))
                 (capBypassCount (+ (. h capBypassCount) 1))
                 (dirtyPasted true)))))
    (setDirtyInput
      (action setDirtyInput ()
        (if (guard strip-control-chars-on-set true false)
          (set-h (inputBytes 2)
                 (cursor 2)
                 (cursorAligned true)
                 (editorSynced true))
          (set-h (inputBytes 3)
                 (cursor 3)
                 (controlLeakCount (+ (. h controlLeakCount) 1))))))
    (moveCursorGrapheme
      (action moveCursorGrapheme ()
        (if (> (. h cursor) 0)
          (if (guard align-cursor-grapheme-boundary true false)
            (set-h (cursor (- (. h cursor) 1))
                   (cursorAligned true))
            (set-h (cursor (- (. h cursor) 1))
                   (cursorAligned false)))
          (keep-h))))
    (clearAndReclaim
      (action clearAndReclaim ()
        (if (> (. h inputBytes) 0)
          (set-h (inputBytes 0)
                 (cursor 0)
                 (cursorAligned true)
                 (editorSynced true))
          (keep-h))))
    (step
      (action step ()
        (any insertCleanChunk
             pasteLargeYank
             setDirtyInput
             moveCursorGrapheme
             clearAndReclaim))))
  safety:
  '(and (<= (. h inputBytes) (. h maxBytes))
        (<= (. h cursor) (. h inputBytes))
        (>= (. h cursor) 0)
        (. h cursorAligned)
        (. h editorSynced)
        (= (. h capBypassCount) 0)
        (= (. h controlLeakCount) 0))
  traces:
  '((checkSanitizationSafe
      (action checkSanitizationSafe ()
        (all (assert (. h dirtyPasted))
             (assert (<= (. h inputBytes) (. h maxBytes)))
             (assert (<= (. h cursor) (. h inputBytes)))
             (assert (. h cursorAligned))
             (assert (. h editorSynced))
             (assert (= (. h capBypassCount) 0))
             (assert (= (. h controlLeakCount) 0))
             (assert safety)
             (keep-h))))
    (checkSanitizationViolated
      (action checkSanitizationViolated ()
        (all (assert (or (> (. h inputBytes) (. h maxBytes))
                         (> (. h capBypassCount) 0)
                         (> (. h controlLeakCount) 0)
                         (not (. h cursorAligned))))
             (assert (not safety))
             (keep-h))))
    (sanitizationEnvelopeSafeTest
      (run sanitizationEnvelopeSafeTest
        (then init
              insertCleanChunk
              pasteLargeYank
              moveCursorGrapheme
              setDirtyInput
              clearAndReclaim
              checkSanitizationSafe)))
    (pasteCapBypassRefutedTest
      (run pasteCapBypassRefutedTest
        (then init pasteLargeYankUncapped checkSanitizationViolated)))
    (controlCharInjectionRefutedTest
      (run controlCharInjectionRefutedTest
        (then init setDirtyInputUnstripped checkSanitizationViolated)))
    (cursorMidGraphemeRefutedTest
      (run cursorMidGraphemeRefutedTest
        (then init insertCleanChunk moveCursorMidGrapheme checkSanitizationViolated))))
  countermodels:
  (list PasteCapBypassCountermodel
        ControlCharInjectionCountermodel
        CursorMidGraphemeSplitCountermodel)
  limits: "Finite 4-unit byte-cap and cursor-alignment abstraction; verifies uniform cap enforcement across insert/paste/set paths, control-character sanitization, and grapheme boundary alignment, not full Unicode bidi layout or terminal font shaping.")

(.def (PasteCapBypassCountermodel @ SearchBoxInputSanitizationEnvelopeModel)
  identity: 'engineering.concurrency.search-box-input-sanitization-envelope.paste-cap-bypass
  dropped-guard: 'cap-yank-paste-bytes
  step-action: "stepPasteCapBypass"
  derive-from-transition: 'pasteLargeYank
  derive-action-name: 'pasteLargeYankUncapped
  expected-itf-predicate: "h.capBypassCount > 0")

(.def (ControlCharInjectionCountermodel @ SearchBoxInputSanitizationEnvelopeModel)
  identity: 'engineering.concurrency.search-box-input-sanitization-envelope.control-char-injection
  dropped-guard: 'strip-control-chars-on-set
  step-action: "stepControlCharInjection"
  derive-from-transition: 'setDirtyInput
  derive-action-name: 'setDirtyInputUnstripped
  expected-itf-predicate: "h.controlLeakCount > 0")

(.def (CursorMidGraphemeSplitCountermodel @ SearchBoxInputSanitizationEnvelopeModel)
  identity: 'engineering.concurrency.search-box-input-sanitization-envelope.cursor-mid-grapheme-split
  dropped-guard: 'align-cursor-grapheme-boundary
  step-action: "stepCursorMidGraphemeSplit"
  derive-from-transition: 'moveCursorGrapheme
  derive-action-name: 'moveCursorMidGrapheme
  expected-itf-predicate: "not(h.cursorAligned)")
