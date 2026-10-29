;;; One declared Project source root, using existing per-owner source annotations.
(import :yuanxu/module-system/selection/init-syntax)
(yuanxu! source: "../../library" mode: explicit
 (backpressure-memory @ "../../library/concurrency/resource-control/backpressure-memory/abstract")
 (rust-resources @ "../../library/drivers/rust-resources")
 (project-organization @ "../../library/project-organization")
 (project-formation @ "../../library/drivers/project-formation")
 (library-project-formation @ "../../scenarios/project-formation"))
