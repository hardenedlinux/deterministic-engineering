;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-only

(import "../projects/library-formation/init.ss" "../profiles/library-formation.ss"
        "library-formation-output.ss" :clan/poo/object
        (only-in :yuanxu/module-system/source/admission current-module-source-observer))
(export main)
(def (main output)
 (when (file-exists? output) (error "formation output must be fresh" output))
 (parameterize ((current-module-source-observer
   (lambda (kind amount)
     (when (and (pair? kind) (memq (car kind) '(link-stage-start link-stage-end)))
       (displayln "FORMATION-SOURCE-STAGE " kind " " amount) (force-output)))))
 (def scene (.get deterministic-engineering/projects/library-formation.init.exports modules library-project-formation scope))
 (def input ((.ref scene 'inputs) LibraryFormationProfile))
 (def result ((.ref scene 'run) LibraryFormationProfile))
 (write-formation-investigation output input result (.ref scene 'render) "declared-project-scope-observed")))
