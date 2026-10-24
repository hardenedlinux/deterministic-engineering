;;; One declared Project source root, using existing per-owner source annotations.
(import :yuanxu/module-system/selection/init-syntax)
(yuanxu! source: "../../modules" mode: explicit
 (backpressure-memory @ "../../library/concurrency/resource-control/backpressure-memory/abstract")
 (rust-resources @ "../../library/concurrency/resource-control/backpressure-memory/rust")
 (project-organization @ "../../library/project-organization")
 (project-formation @ "../../modules/project-formation")
 (library-project-formation @ "../../scenarios/project-formation"))
