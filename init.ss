;;; -*- Gerbil -*-
(import :yuanxu/module-system/selection/init-syntax)

;; Library knowledge and inference are reusable; the gateway is one application.
;; Independent Profile values live in profiles/gateway.ss, outside Module ownership.
(yuanxu!
 :load-modules "./modules" mode: explicit rename: Modules
 (backpressure-memory @ "./library/concurrency/resource-control/backpressure-memory/abstract")
 (rust-resources @ "./library/concurrency/resource-control/backpressure-memory/rust")
 (resource-evidence)
 :load-modules "./scenarios" mode: explicit rename: Scenarios
 (gateway-review)
 (resource-lifecycle))
