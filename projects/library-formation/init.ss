;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;;; One declared Project source root, using existing per-owner source annotations.
(import :yuanxu/module-system/selection/init-syntax)
(yuanxu! source: "../../library" mode: explicit
 (backpressure-memory @ "../../library/backpressure-memory")
 (backpressure-tokio-rayon @ "../../library/backpressure-tokio-rayon")
 (rust-resources @ "../../library/rust-resources")
 (project-organization @ "../../library/project-organization")
 (project-formation @ "../../library/project-formation")
 (project-intake @ "../../library/project-intake"))
