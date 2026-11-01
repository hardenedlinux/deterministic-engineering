;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-only

(import :clan/poo/object :std/encoding/json)
(export write-formation-investigation)
(def (write-formation-investigation output input result render-model entry)
 (when (file-exists? output) (error "formation output must be fresh" output))
 (create-directory output)
 (def report (make-hash-table))
 (hash-put! report "entry" entry)
 (hash-put! report "authority" "design-consequences-only")
 (hash-put! report "finished" (.ref result 'finished))
 (hash-put! report "inputs" (map (lambda (entry) (cons (symbol->string (car entry)) (cdr entry))) input))
 (for-each (lambda (binding)
   (hash-put! report (symbol->string (car binding)) ((.ref result 'rows-of) (cdr binding))))
   ((.ref result 'output-bindings)))
 (call-with-output-file (path-expand "report.json" output) (cut write-json <> report))
 (call-with-output-file (path-expand "project.sysml" output)
  (lambda (p) (display (render-model result) p)))
 (displayln "FORMATION-REPORT " (path-expand "report.json" output))
 (displayln "FORMATION-MODEL " (path-expand "project.sysml" output))
 (displayln "FORMATION-OK"))
