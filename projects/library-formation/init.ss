;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; One declared Project source root, using existing per-owner source annotations.
(import :yuanxu/module-system/selection/init-syntax)
(yuanxu! source: "../../library" mode: explicit
 (backpressure-memory @ "../../library/concurrency/resource-control/backpressure-memory/abstract")
 (backpressure-tokio-rayon @ "../../library/concurrency/resource-control/backpressure-memory/tokio-rayon")
 (rust-resources @ "../../library/drivers/rust-resources")
 (project-organization @ "../../library/project-organization")
 (project-formation @ "../../library/drivers/project-formation")
 (library-project-formation @ "../../scenarios/project-formation"))
