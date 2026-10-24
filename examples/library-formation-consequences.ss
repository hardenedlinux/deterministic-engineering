;; Algorithm probe: does not acquire or qualify the declared Project Scope.
(import "../modules/project-formation/func.ss"
        "../scenarios/project-formation/func.ss"
        "../library/project-organization/config.ss"
        "../profiles/library-formation.ss"
        "library-formation-output.ss")
(export main)
(def (main output)
 (when (file-exists? output) (error "formation output must be fresh" output))
 (def input (formation-inputs Config LibraryFormationProfile))
 (def result (reason-project-formation input))
 (write-formation-investigation output input result render-formation-model "module-functions-probe"))
