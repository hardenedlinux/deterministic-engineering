;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
(import "../../projects/library-formation/init.ss"
        "library-formation-output.ss" :clan/poo/object
        (only-in :yuanxu/module-system/source/admission current-module-source-observer))
(import :deterministic-engineering/init)
(def LibraryFormationProfile (.get deterministic-engineering.init.exports Library library-formation-profiles profiles LibraryFormationProfile))
(export main)
(def (main output)
 (when (file-exists? output) (error "formation output must be fresh" output))
 (parameterize ((current-module-source-observer
   (lambda (kind amount)
     (when (and (pair? kind) (memq (car kind) '(link-stage-start link-stage-end)))
       (displayln "FORMATION-SOURCE-STAGE " kind " " amount) (force-output)))))
 (def scene (.get deterministic-engineering/projects/library-formation.init.exports modules project-intake))
 (def input ((.ref scene 'inputs) LibraryFormationProfile))
 (def result ((.ref scene 'run) LibraryFormationProfile))
 (write-formation-investigation output input result (.ref scene 'render) "declared-project-scope-observed")))
