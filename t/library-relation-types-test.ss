;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; -*- Gerbil -*-
(import
  :std/test
  (only-in :clan/poo/mop validate TypeError?)
  "../types.ss")

(export
  library-relation-types-test)

(def library-relation-types-test
  (test-suite "Shared native Pair relation boundaries"
    (test-case "proper typed rows retain their identity during validation"
      (def pair (list 'a 'b))
      (def triple (list 'a 'b 'c))
      (def binding (list 'usage 'source "sha256:observed"))
      (check-equal? (eq? (validate LibrarySymbolPair pair) pair) #t)
      (check-equal? (eq? (validate LibrarySymbolTriple triple) triple) #t)
      (check-equal? (eq? (validate LibraryScopeBinding binding) binding) #t))

    (test-case "missing, extra, improper and mistyped cells cannot become a rule row"
      (for-each
       (lambda (value)
         (check-exception (validate LibrarySymbolPair value) TypeError?))
       '(() (a) (a b c) (a . b) (a "b")))
      (for-each
       (lambda (value)
         (check-exception (validate LibrarySymbolTriple value) TypeError?))
       '((a b) (a b c d) (a b . c) (a "b" c)))
      (for-each
       (lambda (value)
         (check-exception (validate LibraryScopeBinding value) TypeError?))
       '((usage source) (usage source "ref" extra) (usage source . "ref")
         (usage source "") ("usage" source "ref") (usage "source" "ref")
         (usage source 7))))))
