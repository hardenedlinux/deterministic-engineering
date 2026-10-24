;;; Project test policy on Core's actual source / TestingScript / Fixture / Ops.
(import :clan/poo/object
        (only-in "../projects/library-formation/init.ss"
          deterministic-engineering/projects/library-formation.init.exports))
(export main)
(def (main file expected-cases)
  (def count (string->number expected-cases))
  (unless (and (exact-integer? count) (> count 0)) (error "positive expected case count required"))
  (def demand (.call (.get deterministic-engineering/projects/library-formation.init.exports tests)
                     .for-files (list (path-expand file))))
  (def source-files (.get demand spec))
  (.def (Run @ (.get demand execution))
    runtime-options: '("-:max-heap=2G,debug=q")
    command: (append '("gxtest" "-:max-heap=2G,debug=q" "-v" "5") source-files)
    case-count: count
    profile: =>.+ (.o max-duration-milliseconds: 120000))
  (def receipt (.call Run .run))
  (display (.get receipt output)))
