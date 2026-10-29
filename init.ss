;;; -*- Gerbil -*-
(import :yuanxu/module-system/selection/init-syntax)

;; Framework knowledge/drivers and language engineering have distinct owners.
(yuanxu!
  :load-modules "./library" mode: explicit rename: Library
  (backpressure-memory @ "./library/concurrency/resource-control/backpressure-memory/abstract")
  (evidence @ "./library/drivers/evidence")
  :load-modules "./languages-engineering" mode: explicit rename: Languages
  (rust-resources @ "./languages-engineering/rust/concurrency/resource-control/backpressure-memory")
  :load-modules "./scenarios" mode: explicit rename: Scenarios
  (gateway-review)
  (resource-lifecycle))
