;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Retained real-tool evidence, using the same selected owners as the tests.
(import "source-contracts.ss" :clan/poo/object :std/encoding/json :gerbil-ascent/program/session
        (only-in :std/source this-source-file)
                    (only-in :yuanxu/module-system/interface yuanxu-load-modules))
(export main)

(def (wire rows)
  (map (lambda (row) (map (lambda (value)
                           (if (symbol? value) (symbol->string value) value)) row)) rows))
(def (main output cbmc-path goto-cc-path instrument-path cc-path cxx-path)
  (def project-directory (path-expand "../.." (path-directory (this-source-file))))
  (set! output (path-expand output project-directory))
  (when (file-exists? output) (error "fresh evidence output required" output))
  (create-directory output)
  (def module-view
    (yuanxu-load-modules (path-expand "t/support/source-contract-modules.ss" project-directory)))
  (def selected (.get module-view modules Library))
  (def profile-library (.get selected source-contract-profiles))
  (def driver
    (source-contract-test-support (.get profile-library plan-library) (.get selected evidence)))
  (def evidence (.get driver evidence))
  (def profiles (.get profile-library profiles))
  (def tool-paths (.o cbmc: cbmc-path goto-cc: goto-cc-path goto-instrument: instrument-path
                 cc: cc-path cxx: cxx-path))
  (def selected-runner driver)
  (def queries '())
  (for-each
    (lambda (choice)
      (def selected-entry (.get (.ref selected (car choice)) entry))
      (def selected-profile (.ref profiles (cadr choice)))
      (def usage-id (.get selected-profile identity))
      (def leaf
        (.o (:: @ (.get driver input))
          scenario:
          (.o (:: @ (.get driver plan-library scenario))
            root: project-directory entry: selected-entry profile: selected-profile)
          tools: tool-paths
          module-owner: module-view
          driver: selected-runner))
      (def session
        ((.get evidence open-review) selected-entry
          (.o factors: (list (.get selected-profile factor))) usage-id
          ((.get driver snapshot) leaf) ((.get driver scopes) leaf usage-id)))
      (def result
        (.call leaf .verify (path-expand (symbol->string usage-id) output)))
      ((.get driver register!) session (list result))
      (def answer (gerbil-ascent-session-run session))
      (def (rows relation) ((.get answer rows-of) relation))
      (unless (and (= (length (rows 'unopposed_support)) 1)
                   (null? (rows 'pending)) (null? (rows 'counter)))
        (error "source-contract acceptance query disagrees with independent gold" usage-id))
      (set! queries
        (cons (hash ("usage" (symbol->string usage-id))
                    ("support" (wire (rows 'support)))
                    ("unopposedSupport" (wire (rows 'unopposed_support)))
                    ("pending" (wire (rows 'pending)))
                    ("counter" (wire (rows 'counter)))
                    ("observation" ((.get driver record) result))) queries)))
    '((bounded-capacity capacity-contract) (bounded-capacity capacity-body)
      (bounded-capacity capacity-callers) (bounded-capacity capacity-native)
      (resource-lifetime lifetime-body) (resource-lifetime lifetime-native)))
  (def path (path-expand "report.json" output))
  (call-with-output-file path
    (lambda (port)
      (write-json
        port
        (hash ("schema" "source-contract.acceptance.v1")
              ("queries" (reverse queries))
              ("boundary" "Selected local native dependencies; no whole-project proof or execution permission")))
      (newline port)))
  (displayln "SOURCE-CONTRACT-EVIDENCE-OK " path))
