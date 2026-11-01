;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-only

(import :std/test :clan/poo/object
 (only-in :std/source this-source-file)
 "../projects/library-formation/init.ss" "../profiles/library-formation.ss")
(export codex-capture-test)
(def codex-capture-test
 (test-suite "Same-owner local authority enters actual capture preparation"
  (test-case "original limited role authority discharges only its own obligation"
   (def scene (.get deterministic-engineering/projects/library-formation.init.exports modules library-project-formation scope))
   (def root (path-expand ".." (path-directory (this-source-file))))
   (def original ((.get scene acquire-codex) (getenv "CODEX_THREAD_ID") (getenv "CODEX_SOURCE_TURN")
     (string-split (getenv "CODEX_SOURCE_MESSAGES") #\,) root 120))
   (def authority ((.get scene authorize-codex) original))
   (def request (.o purpose: 'repository-design root: (path-expand ".." (path-directory (this-source-file))) profile: LibraryFormationProfile))
   (def prepared ((.get scene prepare-capture) request authority))
   (check-equal? (.get prepared status) 'capture-blocked)
   (check-equal? (.get prepared capture) #f)
   (check-equal? (.get prepared local-authority roles) '(project-owner implementation-owner))
   (check-equal? (map (cut .get <> role)
     (filter (lambda (f) (eq? (.get f kind) 'missing-original-source-capability)) (.get prepared findings)))
     '(user-confirmation proposal-occurrence))
   (check-equal? (length (filter (lambda (f) (eq? (.get f kind) 'unacquired-method-footprint)) (.get prepared findings))) 4)
   (check-exception ((.get scene prepare-capture) request (.get prepared local-authority)) error?))))
