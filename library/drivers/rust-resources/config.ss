;;; -*- Gerbil -*-
(import
  :clan/poo/object
  "objects.ss")
(export
  Config)
(def Config
  (.o
    purpose: 'rust-resource-specialization
    coding-policy: BackpressureCodingPolicy
    design-policy: BackpressureDesignPolicy))
