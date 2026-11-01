;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-only

;;; Real repository file acquisition, using Core's source/currentness authority.
;;; This observation does not attest user confirmation, role mandate or final C.
(import
  :clan/poo/object
  (only-in :clan/poo/mop validate)
  (only-in :yuanxu/modules/json-schema/json-schema-source yuanxu-json-schema-read-port)
  (only-in :std/source this-source-file)
  (only-in :yuanxu/modules/json-schema/contracts schema-value-contract)
  (only-in :std/string/path path-absolute?)
  (only-in
   :yuanxu/module-system/source/admission
   module-source-type
   module-source-read
   module-source-admit-current!
   call-with-module-source-fresh-reads))
(export
  formation-acquire-inputs
  formation-inputs-current!
  formation-input-observation)
(defstruct repository-inputs (root observations deadline) final: #t)
(def (now) (real-time))
(def (directory-chain! directory)
  (unless (eq? (module-source-type directory) 'directory)
    (error "project input ancestor must be an ordinary directory" directory))
  (def parent (path-directory (path-strip-trailing-directory-separator directory)))
  (unless (equal? parent directory) (directory-chain! parent)))
(def (relative-name? value)
  (and
   (string? value)
   (not (string-empty? value))
   (not (path-absolute? value))
   (andmap
    (lambda (part) (and (not (string-empty? part)) (not (member part '("." "..")))))
    (string-split value #\/))))
(def (formation-acquire-inputs root-input relative-paths max-bytes lifetime-seconds)
  ;; Yuanxu owns structural constraints and their precise Schema diagnostics.
  ;; Resolve the actual schema source at the request boundary, not a stale cache.
  (def request-contract
    (call-with-module-source-fresh-reads
      (lambda ()
        (schema-value-contract 'engineering/repository-input-request
          (call-with-input-string
            (module-source-read
              (path-expand "repository-input.schema.json" (path-directory (this-source-file))))
            yuanxu-json-schema-read-port)))))
  (validate request-contract
    (.o root: root-input paths: relative-paths maxBytes: max-bytes lifetimeSeconds: lifetime-seconds))
  ;; Path traversal and native byte accounting remain filesystem semantics.
  (unless (and (andmap relative-name? relative-paths) (exact-integer? max-bytes))
    (error "invalid repository path or exact native byte bound"))
  (def selected-root (path-expand root-input))
  (def deadline (+ (now) lifetime-seconds))
  (def total 0)
  (def observations
    (map
     (lambda (relative)
       (def path (path-expand relative selected-root))
       (directory-chain! (path-directory path))
       (unless (eq? (module-source-type path) 'regular)
         (error "required project input missing or not regular" relative))
       (def expected-size (file-info-size (file-info path #f)))
       (set! total (+ total expected-size))
       (when (> total max-bytes) (error "project input byte bound exceeded"))
       (def content (module-source-read path))
       ;; Refuse growth between stat and read as well as across the whole closure.
       (when (not (= (u8vector-length (string->utf8 content)) expected-size))
         (error "project input changed while acquiring" relative))
       (cons path content))
     relative-paths))
  (def acquired (make-repository-inputs selected-root observations deadline))
  (formation-inputs-current! acquired)
  acquired)
(def (formation-inputs-current! acquired)
  (unless (repository-inputs? acquired) (error "original repository acquisition required"))
  (when (>= (now) (repository-inputs-deadline acquired)) (error "repository acquisition expired"))
  (call-with-module-source-fresh-reads
   (lambda ()
     (for-each
      (lambda (row) (directory-chain! (path-directory (car row))))
      (repository-inputs-observations acquired))
     (module-source-admit-current!
      (repository-inputs-observations acquired)
      "repository input changed; reacquire, do not relabel original observation")))
  acquired)
(def (formation-input-observation acquired)
  (formation-inputs-current! acquired)
  ;; Copies are documentary content, never an acquisition constructor.
  (.o
    status: 'repository-observation
    root: (string-copy (repository-inputs-root acquired))
    inputs: (map
             (lambda (row) (list (string-copy (car row)) (string-copy (cdr row))))
             (repository-inputs-observations acquired))
    missing-origins: '(user-confirmation proposal-occurrence role-mandate)))
