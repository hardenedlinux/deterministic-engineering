;;; -*- Gerbil -*-
(import
  :clan/poo/object
  "../../profiles/gateway.ss")
(export
  Config)
(def Config
  (.o
    profile: LocalProfile))
