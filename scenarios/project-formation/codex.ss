;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Actual Codex read transport. This is an observation, not a historical-actor attester.
(import
  :clan/poo/object
  :std/encoding/json
  "objects.ss"
  (only-in :std/source this-source-file)
  (only-in :std/io/tempfile call-with-temporary-directory)
  (only-in :std/misc/ports read-all-as-u8vector)
  (only-in :std/crypto/digest sha256)
  (only-in :std/encoding/hex hex-encode)
  (only-in :yuanxu/ops/process-script ProcessScript.)
  (only-in
   :yuanxu/contribution/verification
   yuanxu-verification-adapter
   yuanxu-verify
   yuanxu-verification-valid?
   yuanxu-revoke-verification!))
(export
  formation-acquire-codex
  formation-codex-current!
  formation-codex-observation
  formation-verify-codex
  formation-codex-verification-current!
  formation-revoke-codex!
  formation-authorize-codex
  formation-codex-authorized!
  formation-codex-authority-observation)
(def transport (path-expand "codex-source.py" (path-directory (this-source-file))))
(def consent-source (path-expand "objects.ss" (path-directory (this-source-file))))
(defstruct codex-inputs (thread turn messages root basis deadline transport-digest) final: #t)
(def (digest path)
  (unless (eq? (file-info-type (file-info path #f)) 'regular)
    (error "ordinary source executable required" path))
  (hex-encode (sha256 (call-with-input-file path read-all-as-u8vector))))
(def (bounded-id? value)
  (and (string? value) (> (string-length value) 0) (<= (string-length value) 256)))
(def (read-codex thread-id turn-id message-ids)
  (call-with-temporary-directory
   "codex-source"
   (lambda (directory)
     (def log (path-expand "read.json" directory))
     (def result
       (.call
        (.cc ProcessScript. 'command
             (append
              (list "python3" "-I" transport "--thread" thread-id "--turn" turn-id)
              (apply append (map (lambda (id) (list "--message" id)) message-ids)))
             'directory directory 'timeout 30 'log log 'check-status #f)
        .run))
     (unless (= (.get result status) 0)
       (error "actual Codex read operation failed" (.get result status)))
     (when (> (file-info-size (file-info log #f)) 1048576)
       (error "Codex observation byte bound exceeded"))
     (call-with-input-file log (cut read-json <> object-as-hash: #t)))))
(def (account-key value)
  (and (hash-table? value) (list (hash-ref value "type" #f) (hash-ref value "emailSha256" #f))))
(def (basis-key value)
  (list
   (account-key (hash-ref value "accountBefore" #f))
   (account-key (hash-ref value "accountAfter" #f))
   (hash-ref value "threadId")
   (hash-ref value "cwd")
   (hash-ref value "executable")
   (hash-ref value "executableSha256")
   (let (latest (hash-ref value "latestUser"))
     (list (hash-ref latest "turnId") (hash-ref latest "messageId"))
     (map
      (lambda (row)
        (def item (hash-ref row "item"))
        (list
         (hash-ref row "turnId")
         (hash-ref item "type")
         (hash-ref item "id")
         (hash-ref item "clientId" #f)
         (map
          (lambda (content) (list (hash-ref content "type") (hash-ref content "text")))
          (hash-ref item "content"))))
      (hash-ref value "messages")))))
(def (admit-basis! basis thread-id turn-id message-ids root)
  (def before (hash-ref basis "accountBefore" #f))
  (def after (hash-ref basis "accountAfter" #f))
  (unless (and
           (hash-table? before)
           (equal? (account-key before) (account-key after))
           (equal? (hash-ref before "type" #f) "chatgpt")
           (bounded-id? (hash-ref before "emailSha256" #f)))
    (error "Codex account unavailable or changed within observation"))
  (unless (equal? thread-id (hash-ref basis "threadId" #f))
    (error "Codex thread association differs"))
  (unless (equal?
           (path-strip-trailing-directory-separator (path-normalize (path-expand root)))
           (path-strip-trailing-directory-separator (path-normalize (path-expand (hash-ref basis "cwd")))))
    (error "Codex repository association differs" root (hash-ref basis "cwd")))
  (unless (equal?
           message-ids
           (map (lambda (row) (hash-ref (hash-ref row "item") "id")) (hash-ref basis "messages")))
    (error
     "required original Codex messages are absent or different"
     message-ids
     (map (lambda (row) (hash-ref (hash-ref row "item") "id")) (hash-ref basis "messages"))))
  (for-each
   (lambda (row)
     (def item (hash-ref row "item"))
     (unless (and
              (equal? turn-id (hash-ref row "turnId" #f))
              (equal? (hash-ref item "type" #f) "userMessage")
              (pair? (hash-ref item "content"))
              (andmap
               (lambda (content)
                 (and
                  (equal? (hash-ref content "type") "text")
                  (string? (hash-ref content "text"))))
               (hash-ref item "content")))
       (error "original text user-message occurrence required")))
   (hash-ref basis "messages"))
  (unless (equal? (hash-ref basis "executableSha256") (digest (hash-ref basis "executable")))
    (error "actual Codex executable changed"))
  basis)
(def (formation-acquire-codex thread-id turn-id message-ids root lifetime)
  (unless (and
           (bounded-id? thread-id)
           (bounded-id? turn-id)
           (string? root)
           (list? message-ids)
           (pair? message-ids)
           (<= (length message-ids) 16)
           (andmap bounded-id? message-ids)
           (let loop
               ((ids message-ids))
             (or (null? ids) (and (not (member (car ids) (cdr ids))) (loop (cdr ids)))))
           (real? lifetime)
           (> lifetime 0)
           (<= lifetime 120))
    (error "invalid bounded Codex source request"))
  (def deadline (+ (real-time) lifetime))
  (def before (list (digest transport) (digest consent-source)))
  (def basis
    (admit-basis! (read-codex thread-id turn-id message-ids) thread-id turn-id message-ids root))
  (unless (and (equal? before (list (digest transport) (digest consent-source))) (< (real-time) deadline))
    (error "Codex source changed or expired during acquisition"))
  (make-codex-inputs
   (string-copy thread-id)
   (string-copy turn-id)
   (map string-copy message-ids)
   (path-normalize (path-expand root))
   basis
   deadline
   before))
(def (formation-codex-current! original)
  (unless (codex-inputs? original)
    (error "original Codex observation required; exported JSON is documentary"))
  (unless (and
           (< (real-time) (codex-inputs-deadline original))
           (equal? (codex-inputs-transport-digest original) (list (digest transport) (digest consent-source))))
    (error "Codex observation expired or transport changed"))
  (def fresh
    (admit-basis!
     (read-codex
      (codex-inputs-thread original)
      (codex-inputs-turn original)
      (codex-inputs-messages original))
     (codex-inputs-thread original)
     (codex-inputs-turn original)
     (codex-inputs-messages original)
     (codex-inputs-root original)))
  (unless (and
           (equal? (basis-key fresh) (basis-key (codex-inputs-basis original)))
           (< (real-time) (codex-inputs-deadline original))
           (equal? (codex-inputs-transport-digest original) (list (digest transport) (digest consent-source))))
    (error "Codex account or original message basis changed; reacquire"))
  original)
(def (formation-codex-observation original)
  (unless (and
           (codex-inputs? original)
           (< (real-time) (codex-inputs-deadline original))
           (equal? (codex-inputs-transport-digest original) (list (digest transport) (digest consent-source))))
    (error "current original Codex observation required"))
  (.o
    status: 'codex-account-and-message-observation
    basis: (call-with-input-string
            (json->string (codex-inputs-basis original))
            (cut read-json <> object-as-hash: #t))
    historical-actor-binding: 'unavailable
    authority: 'observation-only))

;; The expected source owner fixes operation and real clock. There is no caller verifier.
;; This verifies only the supported local account/text observation, not C or a role grant.
(defstruct codex-verification (original receipt) final: #t)
(def (instant) (inexact->exact (floor (* 1000 (real-time)))))
(def source-verifier
  (yuanxu-verification-adapter
   "project-formation/codex-observation"
   (lambda (original _now _until) (formation-codex-current! original) #t)
   (lambda (original)
     (unless (codex-inputs? original) (error "original Codex observation required"))
     (object->string
      (list
       (basis-key (codex-inputs-basis original))
       (codex-inputs-deadline original)
       (codex-inputs-transport-digest original))))))
(def (formation-verify-codex original)
  (unless (codex-inputs? original) (error "original Codex observation required"))
  (def receipt
    (yuanxu-verify
     source-verifier
     original
     (instant)
     (inexact->exact (floor (* 1000 (codex-inputs-deadline original))))))
  (unless (and receipt (yuanxu-verification-valid? source-verifier receipt original (instant)))
    (when receipt (yuanxu-revoke-verification! source-verifier receipt))
    (error "Codex verification expired during actual source operation"))
  (make-codex-verification original receipt))
(def (formation-codex-verification-current! verification)
  (unless (codex-verification? verification) (error "original source verification required"))
  (def original (codex-verification-original verification))
  (unless (yuanxu-verification-valid?
           source-verifier
           (codex-verification-receipt verification)
           original
           (instant))
    (error "Codex verification expired, revoked or changed"))
  (formation-codex-current! original)
  (unless (yuanxu-verification-valid?
           source-verifier
           (codex-verification-receipt verification)
           original
           (instant))
    (error "Codex verification expired, revoked or changed"))
  verification)
(def (formation-revoke-codex! verification)
  (unless (codex-verification? verification) (error "original source verification required"))
  (yuanxu-revoke-verification! source-verifier (codex-verification-receipt verification)))

;; Admission is explicitly local: current host account + exact confirmed user choices.
;; It never interprets a declaration, login or owner role as independent-review authority.
(defstruct codex-authority (verification role-source trust-source) final: #t)
(def (reply-answer item)
  (def content (hash-ref item "content"))
  (and
   (= (length content) 1)
   (let* ((text (hash-ref (car content) "text"))
          (prefix "<send_user_message_question_reply>\n")
          (suffix "\n</send_user_message_question_reply>\n"))
     (and
      (string-prefix? prefix text)
      (string-suffix? suffix text)
      (let (rows
            (call-with-input-string
             (substring text (string-length prefix) (- (string-length text) (string-length suffix)))
             (cut read-json <> object-as-hash: #t)))
        (and (list? rows) (= (length rows) 1) (hash-ref (car rows) "answer" #f)))))))
(def (formation-authorize-codex original)
  (unless (codex-inputs? original) (error "original Codex observation required"))
  (def rows (hash-ref (codex-inputs-basis original) "messages"))
  (def (choice expected)
    (def matching (filter (lambda (row) (equal? (reply-answer (hash-ref row "item")) expected)) rows))
    (unless (= (length matching) 1) (error "one original, explicit local consent choice required"))
    (hash-ref (hash-ref (car matching) "item") "id"))
  (def role-source (choice (.get LocalCodexConsent role-answer)))
  (def trust-source (choice (.get LocalCodexConsent trust-answer)))
  (unless (equal? trust-source (hash-ref (hash-ref (codex-inputs-basis original) "latestUser") "messageId"))
    (error "newer human input requires fresh consent-context evaluation"))
  (make-codex-authority (formation-verify-codex original) role-source trust-source))
(def (formation-codex-authorized! authority purpose root)
  (unless (and (codex-authority? authority) (memq purpose (.get LocalCodexConsent purposes)))
    (error "original local authority for a supported purpose required"))
  (def verification (codex-authority-verification authority))
  (def original (codex-verification-original verification))
  (unless (equal?
           (path-strip-trailing-directory-separator (path-normalize (path-expand root)))
           (path-strip-trailing-directory-separator (codex-inputs-root original)))
    (error "local authority cannot cross repository boundaries"))
  (formation-codex-verification-current! verification)
  authority)
(def (formation-codex-authority-observation authority)
  (unless (codex-authority? authority) (error "original local authority required"))
  (def original (codex-verification-original (codex-authority-verification authority)))
  (.o
    status: 'local-codex-operational-authority
    account-subject: (string-copy (hash-ref (hash-ref (codex-inputs-basis original) "accountBefore") "emailSha256"))
    root: (string-copy (codex-inputs-root original))
    roles: (append (.get LocalCodexConsent roles) '())
    purposes: (append (.get LocalCodexConsent purposes) '())
    role-source: (string-copy (codex-authority-role-source authority))
    trust-source: (string-copy (codex-authority-trust-source authority))
    trust-boundary: (.get LocalCodexConsent trust-boundary)
    limitations: (append (.get LocalCodexConsent limitations) '())))
