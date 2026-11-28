;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Interactive search-box input sanitization, bounded yank/clipboard paste cap,
;;; control-char/ANSI stripping, and grapheme-aligned cursor/sync envelope (SM16).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export SearchBoxInputSanitizationEnvelopeModel)

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
  limits: "Finite 4-unit byte-cap and cursor-alignment abstraction; verifies uniform cap enforcement across insert/paste/set paths, control-character sanitization, and grapheme boundary alignment, not full Unicode bidi layout or terminal font shaping.")
