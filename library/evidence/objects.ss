;;; -*- Gerbil -*-
(import
  :clan/poo/object)
(export
  EvidencePolicy)
(.def EvidencePolicy
  result-kind: 'recorded-only
  closure: 'exact-required-inputs
  outcomes: '(pass fail))
