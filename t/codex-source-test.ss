;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :std/test :clan/poo/object :std/encoding/json
 (only-in :std/source this-source-file)
 "../scenarios/project-formation/codex.ss")
(export codex-source-test)
(def codex-source-test
 (test-suite "Actual Codex account and original-message observations"
  (test-case "bounded requests and documentary replays refuse before host work"
   (check-exception (formation-acquire-codex "" "turn" '("id") "/" 60) error?)
   (check-exception (formation-acquire-codex "thread" "turn" '("id" "id") "/" 60) error?)
   (check-exception (formation-acquire-codex "thread" "turn" '("id") "/" 0) error?)
   (check-exception (formation-codex-current! (.o status: 'codex-account-and-message-observation)) error?))
  (test-case "actual source, limited operational authority and verification revoke"
   (def ids (string-split (getenv "CODEX_SOURCE_MESSAGES") #\,))
   (def root (path-expand ".." (path-directory (this-source-file))))
   (def original (formation-acquire-codex (getenv "CODEX_THREAD_ID") (getenv "CODEX_SOURCE_TURN") ids root 120))
   (def observed (formation-codex-observation original))
   (check-equal? (.get observed status) 'codex-account-and-message-observation)
   (check-equal? (.get observed historical-actor-binding) 'unavailable)
   (check-equal? (.get observed authority) 'observation-only)
   (check-equal? (hash-ref (hash-ref (.get observed basis) "accountBefore") "type") "chatgpt")
   (check-equal? (map (lambda (row) (hash-ref (hash-ref row "item") "id")) (hash-ref (.get observed basis) "messages")) ids)
   (check-exception (formation-codex-current! observed) error?)
   ;; Outward mutation cannot rewrite the private original basis.
   (hash-put! (.get observed basis) "threadId" "forged")
   (check-equal? (eq? (formation-codex-current! original) original) #t)
   (check-equal? (hash-ref (.get (formation-codex-observation original) basis) "threadId") (getenv "CODEX_THREAD_ID"))
   (def authority (formation-authorize-codex original))
   (def grant (formation-codex-authority-observation authority))
   (check-equal? (.get grant roles) '(project-owner implementation-owner))
   (check-equal? (.get grant trust-boundary) 'trusted-local-codex)
   (check-equal? (eq? (formation-codex-authorized! authority 'implementation root) authority) #t)
   (for-each (lambda (purpose) (check-exception (formation-codex-authorized! authority purpose root) error?))
     '(independent-review delivery recipient-adoption))
   (check-exception (formation-codex-authorized! authority 'verification "/private/tmp") error?)
   (check-exception (formation-codex-authorized! grant 'verification root) error?)
   (check-exception (formation-authorize-codex observed) error?)
   (def verification (formation-verify-codex original))
   (check-equal? (eq? (formation-codex-verification-current! verification) verification) #t)
   (check-exception (formation-codex-verification-current! observed) error?)
   (formation-revoke-codex! verification)
   (check-exception (formation-codex-verification-current! verification) error?))))
