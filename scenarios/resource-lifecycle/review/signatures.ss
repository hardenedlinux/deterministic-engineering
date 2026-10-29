;;; -*- Gerbil -*-
;;; Real OpenSSL handoff through Core Ops. Keys belong to a configured test authority.
(import
  :clan/poo/object
  :std/encoding/json
  (only-in :yuanxu/ops/process-script ProcessScript.)
  (only-in :yuanxu/ops/func run-script)
  "./func.ss")
(export
  review-signature-tools)
(def (review-signature-tools executable-value output)
  (def executable (string-copy executable-value))
  (unless (file-exists? output) (create-directory output))
  (def expected (review-file-digest executable))
  (def (current!)
    (unless (equal? expected (review-file-digest executable)) (error "signature tool changed"))
    #t)
  ;; Reuse the native immutable declaration; the public Ops arguments API
  ;; supplies each real command. Ops still validates and executes every call.
  (def script
    (.cc ProcessScript. 'command (list executable) 'directory output
         'timeout 10 'log #f 'check-status #f))
  (def sequence 0)
  (def (run args)
    (current!)
    (set! sequence (+ sequence 1))
    (def log (path-expand (string-append "crypto-" (number->string sequence) ".log") output))
    (def arguments (map string-copy args))
    (def operation (path-expand (string-append "crypto-" (number->string sequence) ".json") output))
    (def (observe phase receipt)
      (def stats (##process-statistics))
      (call-with-output-file
          operation
        (lambda (port)
          (write-json
           port
           (hash
            ("schema" "aitia.crypto-ops-observation/v1")
            ("phase" phase)
            ("argv" (cons executable arguments))
            ("lastGcHeapBytes" (inexact->exact (f64vector-ref stats 15)))
            ("lastGcLiveBytes" (inexact->exact (f64vector-ref stats 17)))
            ("status" (and receipt (.ref receipt 'status)))
            ("seconds" (and receipt (.ref receipt 'seconds))))))))
    (observe "started" #f)
    (def receipt (run-script script arguments))
    (call-with-output-file log (lambda (port) (display (.ref receipt 'output) port)))
    (observe "completed" receipt)
    (unless (equal? expected (review-file-digest executable))
      (error "signature tool changed during verification"))
    (= (.ref receipt 'status) 0))
  (def (generate private public)
    (unless (and
             (run (list "genpkey" "-algorithm" "ED25519" "-out" private))
             (run (list "pkey" "-in" private "-pubout" "-out" public)))
      (error "test-only key generation failed")))
  (def (sign private document signature)
    (unless (run (list "pkeyutl" "-sign" "-rawin" "-inkey" private "-in" document "-out" signature))
      (error "authority signing failed")))
  (def (verify public document signature)
    (and
     (file-exists? document)
     (file-exists? signature)
     (run
      (list "pkeyutl" "-verify" "-pubin" "-inkey" public "-rawin" "-in" document "-sigfile" signature))))
  (let ((selected-current current!)
        (selected-generate generate)
        (selected-sign sign)
        (selected-verify verify))
    (.o
      current!: selected-current
      generate: selected-generate
      sign: selected-sign
      verify: selected-verify)))
