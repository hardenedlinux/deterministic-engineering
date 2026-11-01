;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-only

;;; -*- Gerbil -*-
(import
  :std/test
  :clan/poo/object
  (only-in :clan/poo/mop Type validate element?)
  "../types.ss")
(export
  library-record-types-test)

(def library-record-types-test
  (test-suite "Shared Library native Record boundaries"
    (test-case "published Record contracts have native Type identities"
      (for-each
       (lambda (entry)
         (def descriptor (car entry))
         (check-equal? (element? Type descriptor) #t)
         (check-equal? (.get descriptor sexp) (cadr entry)))
       (list
        (list LibraryReferenceContract 'LibraryReferenceContract)
        (list LibraryAssetContract 'LibraryAssetContract)
        (list LibraryPremiseContract 'LibraryPremiseContract)
        (list LibraryClaimContract 'LibraryClaimContract))))
    (test-case "required fields and domain types remain enforced"
      (def reference
        (.o
          identity: 'rule
          revision: "R1"
          owner: 'library))
      (check-equal? (element? LibraryReferenceContract reference) #t)
      (check-equal? (.get (validate LibraryReferenceContract reference) revision) "R1")
      (def asset
        (.o
          identity: 'asset
          revision: "R1"
          owner: 'library
          kind: 'rust
          relative-path: "src/lib.rs"))
      (check-equal? (element? LibraryAssetContract asset) #t)
      (check-equal? (.get (validate LibraryAssetContract asset) owner) 'library)
      (for-each
       (lambda (value)
         (check-exception (validate LibraryReferenceContract value) (lambda (_) #t)))
       (list
        (.o
          identity: 'rule
          owner: 'library)
        (.cc reference 'revision "")
        (.cc reference 'owner "library")))
      (check-exception
       (validate
        LibraryAssetContract
        (.o
          identity: 'asset
          revision: "R1"
          owner: 'library
          kind: 'unknown
          relative-path: "file"))
       (lambda (_) #t))
      (check-exception
       (validate
        LibraryPremiseContract
        (.o
          identity: 'p
          statement: "premise"
          inputs: '(ok "bad")))
       (lambda (_) #t))
      (check-exception
       (validate
        LibraryClaimContract
        (.o
          identity: 'c
          meaning: "claim"
          premises: '()
          duties: '()
          strength: 'unqualified))
       (lambda (_) #t)))
    (test-case "native Record rejects an undeclared evidence field"
      (check-exception
       (validate
        LibraryReferenceContract
        (.o
          identity: 'rule
          revision: "R1"
          owner: 'library
          invented-permission: #t))
       (lambda (_) #t)))))
