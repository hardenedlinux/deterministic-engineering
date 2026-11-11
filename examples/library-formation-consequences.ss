;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; Algorithm probe: does not acquire or qualify the declared Project Scope.
(import "../library/project-formation/func.ss"
        "../library/project-intake/func.ss"
        "../library/project-organization/config.ss"

        "library-formation-output.ss")
(import :deterministic-engineering/init)
(def LibraryFormationProfile (.get deterministic-engineering.init.exports Library library-formation-profiles profiles LibraryFormationProfile))
(export main)
(def (main output)
 (when (file-exists? output) (error "formation output must be fresh" output))
 (def input (formation-inputs Config LibraryFormationProfile))
 (def result (reason-project-formation input))
 (write-formation-investigation output input result render-formation-model "module-functions-probe"))
