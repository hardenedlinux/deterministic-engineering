;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; -*- Gerbil -*-
;;; Finite authoritative discovery and signed decisions consume existing native owners.
(import
  :clan/poo/object
  :std/encoding/json
  :std/list/list
  (only-in :std/os/pid getpid)
  (only-in :std/crypto/digest sha256)
  (only-in :std/encoding/hex hex-encode)
  :yuanxu/contribution/verification
  :agentic-ai-lab/lambda-aitia/modules/sdlc/objects
  :agentic-ai-lab/lambda-aitia/modules/sdlc/review-authority
  "./func.ss"
  "./reassessment.ss")
(export
  cross-intake-history
  open-cross-intake-group
  open-cross-intake-approval
  review-history-wire
  review-mechanical-basis)
(def (load path) (call-with-input-file path (cut read-json <> object-as-hash: #t)))
(def (clone x) (call-with-input-string (json->string x) (cut read-json <> object-as-hash: #t)))
(def (digest x) (hex-encode (sha256 (string->utf8 x))))
(def (same-set? a b)
  (and
   (= (length a) (length b))
   (= (length a) (length (delete-duplicates/hash a)))
   (every (lambda (x) (and (member x b) #t)) a)))
(.def ReviewArchiveProjection.
  schema: "aitia.review-archive/v1"
  sealed?: #t
  owner: (error "Archive projection requires an owner")
  capture: (error "Archive projection requires a frozen capture")
  technical: (error "Archive projection requires its technical packet")
  roots: (error "Archive projection requires its root references")
  producer-pid: (error "Archive projection requires its producer")
  fields: (list
           (cons "schema" schema)
           (cons "sealed" sealed?)
           (cons "producerPid" producer-pid)
           (cons "owner" owner)
           (cons "cut" (.get capture cut))
           (cons "native" (.get capture native))
           (cons "records" (.get capture records))
           (cons "submissions" (.get capture submissions))
           (cons "origins" (.get capture origins))
           (cons "technicalPacket" technical)
           (cons "rootReferences" roots))
  json: (list->hash-table fields))
(def (review-history-wire owner technical lineage records)
  (call-with-output-string
   (lambda (port)
     (write
      (list
       'aitia-review-owner/v1
       owner
       technical
       lineage
       (map
        (lambda (row)
          (list
           (car row)
           (map
            (lambda (key) (hash-ref (cadr row) key))
            '("signer" "policy" "decision" "supersedes" "target"))
           (caddr row)))
        records))
      port))))
(def (review-mechanical-basis wire)
  (def body (call-with-input-string wire (cut read-json <> object-as-hash: #t)))
  (list
   (map
    (lambda (key) (hash-ref body key))
    '("schema" "policy" "subject" "revision" "scope" "source" "sourceSha256" "sourceBundle" "consumerSourcesSha256"))
   (hash-ref body "failures")
   (hash-ref body "dispositions")
   (map
    (lambda (row)
      (map
       (lambda (key) (hash-ref row key))
       '("id" "claim" "role" "polarity" "source" "sourceIdentity" "digest" "factors" "links")))
    (hash-ref (hash-ref body "history") "clues"))))
(def (review-basis-equivalent? old current)
  (def (data value)
    (if (string? value)
        (call-with-input-string value (cut read-json <> object-as-hash: #t))
        value))
  (let ((old-data (data old)) (current-data (data current)))
    (and
     (= (length old-data) 4)
     (= (length current-data) 4)
     (equal? (car old-data) (car current-data))
     (every same-set? (cdr old-data) (cdr current-data)))))
(def (cross-intake-history bindings acceptance sources)
  (cross-intake-from bindings (open-backpressure-history acceptance sources)))
(def (open-cross-intake-group identities acceptance sources)
  (unless (and (pair? identities) (every string? identities) (same-set? identities identities))
    (error "distinct nonempty intake identities required"))
  (def names (map string-copy identities))
  (def owners (open-backpressure-histories acceptance sources (+ 1 (length names))))
  (def histories
    (let loop
        ((rest owners) (remaining (length names)))
      (if (= remaining 0) '() (cons (car rest) (loop (cdr rest) (- remaining 1))))))
  (def aggregate (list-ref owners (length names)))
  (def bindings
    (map
     (lambda (name history)
       (let ((selected-name name) (selected-history history))
         (.o
           identity: selected-name
           history: selected-history)))
     names
     histories))
  (def federation (cross-intake-from bindings aggregate))
  (let ((selected-histories histories) (selected-federation federation))
    (.o
      histories: selected-histories
      federation: selected-federation)))
(def (cross-intake-from bindings aggregate)
  (def required (map (lambda (binding) (.ref binding 'identity)) bindings))
  (unless (and (pair? required) (same-set? required required))
    (error "duplicate/empty intake mandate"))
  (def (discover-intakes)
    (map
     (lambda (binding)
       (list (.ref binding 'identity) ((.ref (.ref binding 'history) 'capture))))
     bindings))
  (def synced-cut #f)
  (def rebuilds 0)
  (def reuses 0)
  (def (sync!)
    (def captures (discover-intakes))
    (def source-cut
      (digest
       (json->string
        (map
         (lambda (item)
           (list (car item) (hash-ref (cadr (cadr item)) "viewIdentity")))
         captures))))
    (if (equal? source-cut synced-cut)
        (set! reuses (+ reuses 1))
        (let ((seen (make-hash-table)) (missing-set (make-hash-table)) (missing '()))
          (for-each
           (lambda (binding item)
             (def source-history (.ref binding 'history))
             (for-each
              (lambda (clue)
                (def id (hash-ref clue "id"))
                (def entry ((.ref source-history 'reference) id))
                (def prior (hash-ref seen id #f))
                (when (and prior (not (equal? prior (.ref entry 'digest))))
                  (error "same history identity has conflicting content"))
                (hash-put! seen id (.ref entry 'digest))
                (def existing (with-catch (lambda (_) #f) (lambda () ((.ref aggregate 'reference) id))))
                (if existing
                    (unless (equal? (.ref existing 'digest) (.ref entry 'digest)) (error "aggregate history conflict"))
                    (let (path (.ref entry 'path))
                      (unless (hash-key? missing-set path)
                        (hash-put! missing-set path #t)
                        (set! missing (cons path missing))))))
              (hash-ref (car (cadr item)) "clues")))
           bindings
           captures)
          (unless (null? missing) ((.ref aggregate 'add-runs!) (reverse missing)))
          (def snapshot ((.ref aggregate 'exchange) 'snapshot))
          (unless (same-set? (hash-keys seen) (map (cut hash-ref <> "id") (hash-ref snapshot "clues")))
            (error "intake disappearance cannot erase aggregate history"))
          ((.ref aggregate 'observe!) source-cut)
          (set! synced-cut source-cut)
          (set! rebuilds (+ rebuilds 1))))
    captures)
  (def (federation-stats)
    (let ((selected-rebuilds rebuilds) (selected-reuses reuses))
      (.o
        rebuilds: selected-rebuilds
        reuses: selected-reuses)))
  (def (capture-federation) (sync!) ((.ref aggregate 'capture)))
  (def (current-federation!) (sync!) ((.ref aggregate 'current!)))
  (def (capture-current-federation!) (sync!) ((.ref aggregate 'current-capture!)))
  (def required-identities (map string-copy required))
  (.o
    current-capture!: capture-current-federation!
    sync-stats: federation-stats
    capture: capture-federation
    current!: current-federation!
    discover: discover-intakes
    required: required-identities
    registration-stats: (.get aggregate registration-stats)
    reference: (.get aggregate reference)
    capture-stats: (.get aggregate capture-stats)
    entry: (.get aggregate entry)
    source-current!: (.get aggregate source-current!)
    sources: (.get aggregate sources)
    source-seal: (.get aggregate source-seal)))

(def (open-cross-intake-approval
      federation
      mechanical
      tools
      directory
      directory-signature
      root-public
      alice-public
      bob-public
      predecessor:
      (predecessor #f)
      incarnation:
      (incarnation #f)
      persistence:
      (persistence #f))
  ;; A mutable live ancestor cannot be frozen by a successor checkpoint.
  ;; Require the existing closed archive source before durable owner handover.
  (when (and persistence predecessor (not (.slot? predecessor 'reader)))
    (error "durable owner requires a closed archive predecessor; seal and recover first"))
  ;; The trusted host pins the actual predecessor capability before agent input.
  ;; The label is only a signed presentation identity, never source authority.
  (def owner-id
    (if incarnation (string-copy incarnation) (symbol->string (gensym 'aitia-review-owner))))
  (when (and predecessor (.slot? predecessor 'reader) (not (equal? owner-id (.ref predecessor 'reader))))
    (error "archive reader must be the actual successor incarnation"))
  (def available? #t)
  ;; Persistence is host custody, never a deserialized receipt or a second gate.
  (def committed-head (and persistence (string-copy (.ref ((.ref persistence 'selected)) 'digest))))
  (def committed-references '())
  (def (commit-current?)
    (with-catch
     (lambda (_) #f)
     (lambda ()
       (or
        (not persistence)
        (and
         committed-head
         (equal? committed-head (.ref ((.ref persistence 'selected)) 'digest))
         (every (lambda (pair) (equal? (review-file-digest (car pair)) (cadr pair))) committed-references))))))
  (def intake-required (map string-copy (.ref federation 'required)))
  (def predecessor-id (and predecessor (string-copy (.ref predecessor 'owner))))
  (def predecessor-source (and predecessor-id (string-append "predecessor:" predecessor-id)))
  (def required (append intake-required (if predecessor-source (list predecessor-source) '())))
  (def inherited-cut #f)
  (def handover-references '())
  (def retained-predecessor #f)
  (def directory-sha (review-file-digest directory))
  (def root-sha (review-file-digest root-public))
  (def alice-sha (review-file-digest alice-public))
  (def bob-sha (review-file-digest bob-public))
  (def technical-packet (.ref mechanical 'packet))
  (def technical-digest (digest technical-packet))
  (def mechanical-basis (json->string (review-mechanical-basis technical-packet)))
  (def body (call-with-input-string technical-packet (cut read-json <> object-as-hash: #t)))
  (def content-request (.ref mechanical 'content-request))
  (def content (.ref content-request 'facts))
  (unless (and
           (eq? (.ref content-request 'purpose) 'criterion-content)
           (equal? technical-digest (.ref content 'artifact-digest))
           (equal? (.ref content 'standard) "nasa/sdlc/npr-7150.2")
           (equal? (.ref content 'requirement) "SWE-061")
           (equal? (.ref content 'criterion) "SWE-061/p1")
           (every
            (lambda (key) (equal? (.ref content-request key) (hash-ref body (symbol->string key))))
            '(subject revision scope)))
    (error "mechanical packet differs from its native bound content request"))
  (def project
    (sdlc-project (hash-ref body "subject") (hash-ref body "revision") (hash-ref body "scope") #t))
  (def verify (.ref tools 'verify))
  (def source-captures ((.ref federation 'discover)))
  (unless (and
           (equal?
            (hash-ref body "viewIdentity")
            (hash-ref (cadr ((.ref federation 'capture))) "viewIdentity"))
           (equal?
            (map (lambda (item) (hash-ref (cadr (cadr item)) "viewIdentity")) source-captures)
            (map (lambda (item) (hash-ref (cadr (cadr item)) "viewIdentity")) ((.ref federation 'discover)))))
    (error "authority requires the exact current mechanical/source capture"))
  (def source-artifacts
    (map
     (lambda (item)
       (def wire (json->string (cadr item)))
       (list (car item) wire (digest wire)))
     source-captures))
  ;; Accepted authority decisions are append-only within this review family.
  ;; Their content is signed; failed untrusted submissions never become authority decisions.
  (def decisions '())
  (def decision-references (make-hash-table))
  (def decision-bodies (make-hash-table))
  (def decision-origins (make-hash-table))
  (def (decision-current? decision)
    (with-catch
     (lambda (_) #f)
     (lambda ()
       (every
        (lambda (pair) (equal? (review-file-digest (car pair)) (cadr pair)))
        (hash-ref decision-references (car decision))))))
  ;; The actual root signature is verified once. Reuse is conditional on every
  ;; authority input and the verifier binary remaining byte-identical/available.
  (def directory-body (load directory))
  (def root-references
    (map
     (lambda (path) (list path (review-file-digest path)))
     (list directory directory-signature root-public alice-public bob-public)))
  (def root-admitted?
    (and
     (equal? directory-sha (review-file-digest directory))
     (equal? root-sha (review-file-digest root-public))
     (equal? alice-sha (review-file-digest alice-public))
     (equal? bob-sha (review-file-digest bob-public))
     (same-set? intake-required (hash-ref directory-body "sources"))
     (equal? (hash-ref directory-body "requiredSigner") "test-reviewer-a")
     (verify root-public directory directory-signature)))
  (def (root-current?)
    (and
     root-admitted?
     ((.ref tools 'current!))
     (every (lambda (pair) (equal? (cadr pair) (review-file-digest (car pair)))) root-references)))
  (def current-origin
    (list
     directory-sha
     technical-digest
     (hash-ref body "subject")
     (hash-ref body "revision")
     (hash-ref body "scope")))
  (def (origin-target policy origin)
    (digest
     (json->string (append (list "review-family/v1" (car origin) (cadr origin) policy) (cddr origin)))))
  (def (target policy) (origin-target policy current-origin))
  (def (authorized-document? path signature delegation delegation-signature origin)
    (with-catch
     (lambda (_) #f)
     (lambda ()
       (def value (load path))
       (def signer (hash-ref value "signer"))
       (def policy (hash-ref value "policy"))
       (and
        available?
        (root-current?)
        (member policy (hash-ref directory-body "policies"))
        (equal? (hash-ref value "target") (origin-target policy origin))
        (member (hash-ref value "decision") '("approved" "rejected"))
        (list? (hash-ref value "supersedes"))
        (=
         (length (hash-ref value "supersedes"))
         (length (delete-duplicates/hash (hash-ref value "supersedes"))))
        (every
         (lambda (id)
           (and
            (string? id)
            (find
             (lambda (row)
               (and
                (equal? id (car row))
                (equal? (hash-ref (hash-ref decision-bodies (car row)) "decision") "rejected")))
             decisions)
            #t))
         (hash-ref value "supersedes"))
        (or
         (and (equal? signer "test-reviewer-a") (verify alice-public path signature))
         (and
          (equal? signer "test-reviewer-b")
          delegation
          delegation-signature
          (verify bob-public path signature)
          (verify alice-public delegation delegation-signature)
          (let (grant (load delegation))
            (and
             (equal? (hash-ref grant "delegate") signer)
             (equal? (hash-ref grant "publicKey") bob-sha)
             (equal? (hash-ref grant "target") (hash-ref value "target"))
             (equal? (hash-ref grant "supersedes") (hash-ref value "supersedes"))))))))))
  (def (admit-document!
        origin
        path-value
        signature-value
        (delegation-value #f)
        (delegation-signature-value #f)
        current?:
        (check-current? #f))
    (def path (string-copy path-value))
    (def signature (string-copy signature-value))
    (def delegation (and delegation-value (string-copy delegation-value)))
    (def delegation-signature (and delegation-signature-value (string-copy delegation-signature-value)))
    (def references
      (map
       (lambda (path) (list path (review-file-digest path)))
       (filter identity (list path signature delegation delegation-signature))))
    (if (authorized-document? path signature delegation delegation-signature origin)
        (let ((id (review-file-digest path)) (value (load path)))
          (unless (and
                   available?
                   (or (not check-current?) (not predecessor) (not (.slot? predecessor 'reader)) (handover-current?))
                   (equal? id (cadar references))
                   (every (lambda (pair) (equal? (cadr pair) (review-file-digest (car pair)))) references))
            (error "approval inputs changed during actual verification"))
          (unless (find (lambda (d) (equal? (car d) id)) decisions)
            (hash-put! decision-origins id (clone origin))
            (hash-put! decision-references id references)
            (hash-put! decision-bodies id (clone value))
            (set! decisions (append decisions (list (list id path signature delegation delegation-signature)))))
          (string-copy id))
        #f))
  (def (submit! path signature (delegation #f) (delegation-signature #f))
    (if (or
         (not (commit-current?))
         (and predecessor (.slot? predecessor 'reader) (not (handover-current?))))
        #f
        (let* ((before (map car decisions))
               (id (admit-document! current-origin path signature delegation delegation-signature current?: #t)))
          (if (and id persistence (not (member id before)))
              ;; A failed/ambiguous publication is terminal. The accepted negative
              ;; stays retained; no old frame may authorize continued use.
              (with-catch
               (lambda (_) (set! available? #f) #f)
               (lambda () (persist-prefix!) id))
              id))))
  (def (decision-data decision-cut)
    (map
     (lambda (decision)
       (list
        (string-copy (car decision))
        (clone (hash-ref decision-bodies (car decision)))
        (clone (hash-ref decision-references (car decision)))))
     decision-cut))
  (def (accepted-decisions) (decision-data decisions))
  (def (handover-capture)
    (and
     available?
     (handover-current?)
     (let* ((records (decision-data decisions))
            (native
             (review-history-wire
              owner-id
              technical-digest
              (list inherited-cut handover-references)
              records))
            (selected-cut (digest native))
            (selected-owner (string-copy owner-id))
            (selected-records records)
            (selected-native native)
            (selected-submissions (map (lambda (row) (clone (cdr row))) decisions))
            (selected-origins
             (map
              (lambda (row) (list (string-copy (car row)) (clone (hash-ref decision-origins (car row)))))
              decisions))
            (selected-basis (string-copy mechanical-basis))
            (selected-roots (clone root-references)))
       (.o
         owner: selected-owner
         cut: selected-cut
         records: selected-records
         native: selected-native
         submissions: selected-submissions
         origins: selected-origins
         basis: selected-basis
         root-references: selected-roots))))
  (def (predecessor-capture)
    (and
     predecessor
     (or
      (and retained-predecessor (commit-current?) retained-predecessor)
      (with-catch (lambda (_) #f) (lambda () ((.ref predecessor 'handover-capture)))))))
  (def (handover-current?)
    (or
     (not predecessor)
     (with-catch
      (lambda (_) #f)
      (lambda ()
        (def current (predecessor-capture))
        (and
         current
         inherited-cut
         (equal? predecessor-id (.ref current 'owner))
         (equal? inherited-cut (.ref current 'cut))
         (every (lambda (pair) (equal? (cadr pair) (review-file-digest (car pair)))) handover-references))))))
  (def (accept-handover! path-value signature-value)
    (def path (string-copy path-value))
    (def signature (string-copy signature-value))
    (def prior (predecessor-capture))
    (if (not prior)
        'history-discovery-required
        (with-catch
         (lambda (_) 'handover-refused)
         (lambda ()
           (def grant (load path))
           (def references (map (lambda (p) (list p (review-file-digest p))) (list path signature)))
           (def prior-records (.ref prior 'records))
           (if (not
                (and
                 available?
                 (root-current?)
                 (review-basis-equivalent? (.ref prior 'basis) mechanical-basis)
                 (equal? (.ref prior 'root-references) root-references)
                 (equal? (.ref prior 'owner) predecessor-id)
                 (same-set? (hash-keys grant) '("schema" "from" "to" "technicalDigest" "cut" "records"))
                 (equal? (hash-ref grant "schema") "aitia.owner-handover/v1")
                 (equal? (hash-ref grant "from") predecessor-id)
                 (equal? (hash-ref grant "to") owner-id)
                 (equal? (hash-ref grant "technicalDigest") technical-digest)
                 (equal? (hash-ref grant "cut") (.ref prior 'cut))
                 (equal? (hash-ref grant "records") (map car prior-records))
                 ((.ref tools 'verify) root-public path signature)))
               'handover-refused
               (let ((imported
                      (map
                       (lambda (submission)
                         (let* ((id (review-file-digest (car submission)))
                                (entry (assoc id (.ref prior 'origins))))
                           (and entry (apply admit-document! (cadr entry) submission))))
                       (.ref prior 'submissions))))
                 ;; Even partial import retains every accepted negative. It grants no discovery.
                 (if (and
                      available?
                      (equal? imported (map car prior-records))
                      (every
                       (lambda (row)
                         (let (accepted (assoc (car row) (accepted-decisions)))
                           (and accepted (equal? (caddr row) (caddr accepted)))))
                       prior-records)
                      (equal? (.ref prior 'cut) (.ref (predecessor-capture) 'cut))
                      (every (lambda (pair) (equal? (cadr pair) (review-file-digest (car pair)))) references))
                     (begin
                       (set! inherited-cut (string-copy (.ref prior 'cut)))
                       (set!
                        handover-references
                        (delete-duplicates/hash
                         (append
                          references
                          (if (.slot? prior 'storage-references) (clone (.ref prior 'storage-references)) '()))))
                       'handover-accepted)
                     'handover-refused)))))))
  (def (persist-prefix!)
    (unless (and available? (commit-current?) (root-current?)) (error "persistence custody changed"))
    (def capture (or (handover-capture) (error "cannot persist incomplete history")))
    (def imported-prefix (and predecessor (predecessor-capture)))
    (def prefix-capture capture)
    (def value
      (.get
       (.o (:: @ ReviewArchiveProjection.)
           schema: "aitia.review-archive/v2"
           sealed?: #f
           producer-pid: (getpid)
           owner: owner-id
           capture: prefix-capture
           technical: technical-packet
           roots: root-references
           fields: => (cut
                       append
                       <>
                       (list
                        (cons "closure" "accepted-prefix")
                        (cons "previousHead" committed-head)
                        (cons "acceptedCount" (length decisions)))))
       json))
    (def wire (json->string value))
    ;; The trusted host must serialize intent -> write/close -> signed head ->
    ;; current selection. It receives owned bytes and the expected prior pin.
    (def reference ((.ref persistence 'commit!) (string-copy wire) (string-copy committed-head)))
    (def head-path (.ref reference 'path))
    (def head-sha (.ref reference 'digest))
    (def signature-path (string-copy (.ref reference 'signature)))
    (def signature-sha (review-file-digest signature-path))
    (def head (load head-path))
    (unless (and
             available?
             (root-current?)
             (equal? head-sha (review-file-digest head-path))
             (equal? head-sha (.ref ((.ref persistence 'selected)) 'digest))
             (verify root-public head-path signature-path)
             (equal? (hash-ref head "schema") "aitia.recovery-head/v1")
             (equal? (hash-ref head "state") "checkpoint")
             (eq? (hash-ref head "reader") #f)
             (equal? (hash-ref head "owner") owner-id)
             (equal? (hash-ref head "cut") (.ref capture 'cut))
             (equal? (hash-ref head "previousHead") committed-head)
             (equal? (hash-ref head "acceptedCount") (length decisions))
             (equal? (hash-ref head "archiveSha256") (digest wire))
             (equal? (review-file-digest (hash-ref head "archive")) (digest wire))
             (equal? (map car decisions) (map car (.ref capture 'records)))
             (every decision-current? decisions)
             (equal? head-sha (review-file-digest head-path))
             (equal? head-sha (.ref ((.ref persistence 'selected)) 'digest)))
      (error "persistent prefix publication incomplete or changed"))
    (unless (equal? signature-sha (review-file-digest signature-path))
      (error "checkpoint signature changed"))
    (set!
     committed-references
     (list
      (list (string-copy head-path) (string-copy head-sha))
      (list signature-path signature-sha)
      (list (string-copy (hash-ref head "archive")) (string-copy (hash-ref head "archiveSha256")))))
    (set! committed-head (string-copy head-sha))
    ;; The new selected checkpoint now carries the complete imported inventory.
    ;; Keep the admitted predecessor capture for the same native discovery;
    ;; signatures, inherited grant, actual files and current own head still check.
    (when imported-prefix (set! retained-predecessor imported-prefix)))
  (def (retire-chain!)
    (when (and predecessor (.slot? predecessor 'retire-chain!)) ((.ref predecessor 'retire-chain!)))
    (set! available? #f))
  (def (seal-history! path-value retire-predecessor?: (retire? #f))
    (when (and predecessor (.slot? predecessor 'retire-chain!) (not retire?))
      (error "sealing live predecessor history requires explicit host retirement"))
    (def path (string-copy path-value))
    (when (or (file-exists? path) (file-exists? (string-append path ".pending")))
      (error "archive destination must be fresh"))
    (def capture (or (handover-capture) (error "cannot seal incomplete history")))
    (def seal-capture capture)
    (def value
      (.get
       (.o (:: @ ReviewArchiveProjection.)
           producer-pid: (getpid)
           owner: owner-id
           capture: seal-capture
           technical: technical-packet
           roots: root-references)
       json))
    (unless (and available? (equal? (map car decisions) (map car (.ref capture 'records))))
      (error "history advanced while capturing seal"))
    ;; Explicit host custody closes every known live ancestor before archive IO.
    ;; In-flight signature admission rechecks available? before acknowledging.
    (if retire? (retire-chain!) (set! available? #f))
    (call-with-output-file (string-append path ".pending") (cut write-json <> value))
    (rename-file (string-append path ".pending") path)
    (list path (review-file-digest path) (string-copy owner-id) (.ref capture 'cut)))
  (def (frame policy (declared #f))
    (def captures (clone source-captures))
    (def declared-ids (map string-copy (or declared required)))
    (def intake-sources
      (map
       (lambda (item)
         (def observation (cadr item))
         (sdlc-history-source
          (car item)
          (hash-ref (car observation) "ownerIdentity")
          (hash-ref (cadr observation) "viewIdentity")
          (caddr (assoc (car item) source-artifacts))
          #t))
       (filter (lambda (item) (member (car item) declared-ids)) captures)))
    (def captured-handover inherited-cut)
    (def captured-handover-references (clone handover-references))
    (def model-sources
      (append
       intake-sources
       (if predecessor-source
           (list
            (sdlc-history-source
             predecessor-source
             predecessor-id
             (or captured-handover "unavailable")
             (if (pair? handover-references) (cadar handover-references) technical-digest)
             (and (handover-current?) #t)))
           '())))
    (def discovery
      (sdlc-history-discovery
       "cross-intake-history"
       project
       directory-sha
       policy
       (map string-copy required)
       model-sources
       technical-digest))
    (def discovery-request (sdlc-history-request discovery))
    (def decision-cut decisions)
    (def request-rows
      (map
       (lambda (decision)
         (def value (clone (hash-ref decision-bodies (car decision))))
         (def approval
           (sdlc-review-approval
            (car decision)
            project
            "nasa/sdlc/npr-7150.2"
            "SWE-061"
            (hash-ref value "signer")
            (string-append "sha256:" (car decision))
            (string->symbol (hash-ref value "decision"))
            (hash-ref value "target")))
         (list
          decision
          (sdlc-approval-request
           approval
           discovery
           technical-digest
           (hash-ref value "policy")
           supersedes:
           (hash-ref value "supersedes")
           references:
           (clone (hash-ref decision-references (car decision))))))
       decision-cut))
    (def discovery-seal (sdlc-review-authority-snapshot discovery-request))
    (def request-seals
      (map
       (lambda (request) (cons request (sdlc-review-authority-snapshot request)))
       (cons discovery-request (map cadr request-rows))))
    (def (request-current? request)
      (def entry (assq request request-seals))
      (and entry (equal? (cdr entry) (sdlc-review-authority-snapshot request))))
    (def last-check "not-checked")
    (def guards
      (list
       (cons "owner" (lambda () available?))
       (cons "persistent-head" commit-current?)
       (cons "root-authority" root-current?)
       (cons "predecessor" handover-current?)
       (cons "handover-cut" (lambda () (equal? captured-handover inherited-cut)))
       (cons "handover-references" (lambda () (equal? captured-handover-references handover-references)))
       (cons "native-request" (lambda () (request-current? discovery-request)))
       (cons "required-sources" (lambda () (same-set? declared-ids required)))
       (cons "policy" (lambda () (member policy (hash-ref directory-body "policies"))))
       (cons
        "source-views"
        (lambda ()
          (equal?
           (map (lambda (item) (hash-ref (cadr (cadr item)) "viewIdentity")) captures)
           (map (lambda (item) (hash-ref (cadr (cadr item)) "viewIdentity")) ((.ref federation 'discover))))))))
    (def (discovery-current?)
      (with-catch
       (lambda (_) (set! last-check (string-append "error/" last-check)) #f)
       (lambda ()
         (and
          (every (lambda (entry) (set! last-check (car entry)) (and ((cdr entry)) #t)) guards)
          (begin (set! last-check "current") #t)))))
    (def adapter
      (sdlc-review-authority-adapter
       "cross-intake-authority/v1"
       (lambda (request now until)
         (and
          (discovery-current?)
          (request-current? request)
          (or
           (eq? request discovery-request)
           (any
            (lambda (row)
              (def item (car row))
              (and (eq? request (cadr row)) (decision-current? item)))
            request-rows))))))
    (def captured-decisions (map car decision-cut))
    (def packet
      (json->string
       (hash
        ("schema" "aitia.cross-intake-authority-input/v1")
        ("policy" policy)
        ("technicalPacket" technical-packet)
        ("technicalDigest" technical-digest)
        ("requiredSources" required)
        ("declaredSources" declared-ids)
        ("sourceArtifacts" source-artifacts)
        ("rootReferences" root-references)
        ("owner" owner-id)
        ("predecessor" (or predecessor-id #f))
        ("handoverCut" (or captured-handover #f))
        ("handoverReferences" handover-references)
        ("acceptedAtCapture" (decision-data decision-cut))
        ("nativeRequests" (map (lambda (entry) (cdr entry)) request-seals))
        ("receiptMetadataIsAuthority" #f))))
    ;; Every use refreshes the complete technical closure; query reuse alone is
    ;; never a substitute for admission at the actual native gate.
    (def (gate mechanical-receipts authority-receipts now)
      (def technical (reassessment-stage mechanical mechanical-receipts now))
      (def current
        (and
         (discovery-current?)
         (or
          (equal? captured-decisions (map car decisions))
          (begin (set! last-check "decision-inventory") #f))))
      (def usable
        (if current
            (filter
             (lambda (receipt)
               (or
                (yuanxu-verification-valid? adapter receipt discovery-request now)
                (any
                 (lambda (row)
                   (and
                    (decision-current? (car row))
                    (yuanxu-verification-valid? adapter receipt (cadr row) now)))
                 request-rows)))
             authority-receipts)
            '()))
      (def result
        (sdlc-review-authority-gate
         technical
         discovery
         (map cadr request-rows)
         adapter
         usable
         now
         policy:
         policy))
      (let (selected-result result)
        (.o (:: @ selected-result)
            current-use-checked?: #t)))
    (let ((selected-adapter adapter)
          (selected-discovery discovery-request)
          (selected-rows (map (lambda (row) (list (clone (car row)) (cadr row))) request-rows))
          (selected-packet packet)
          (selected-gate gate)
          (selected-model discovery)
          (selected-check (lambda () (string-copy last-check))))
      (.o
        adapter: selected-adapter
        discovery-request: selected-discovery
        approval-requests: selected-rows
        gate: selected-gate
        discovery: selected-model
        packet: selected-packet
        current-check: selected-check)))
  (when (and predecessor (.slot? predecessor 'claim-owner!))
    ((.ref predecessor 'claim-owner!) owner-id))
  (let ((selected-owner (string-copy owner-id))
        (selected-handover handover-capture)
        (selected-accept accept-handover!)
        (selected-seal seal-history!)
        (selected-retire retire-chain!)
        (selected-close (lambda () (set! available? #f)))
        (selected-target target)
        (selected-frame frame)
        (selected-submit submit!)
        (selected-accepted accepted-decisions)
        (selected-digest (string-copy technical-digest)))
    (.o
      owner: selected-owner
      handover-capture: selected-handover
      accept-handover!: selected-accept
      seal-history!: selected-seal
      retire-chain!: selected-retire
      close!: selected-close
      target: selected-target
      frame: selected-frame
      submit!: selected-submit
      accepted-decisions: selected-accepted
      technical-digest: selected-digest)))
