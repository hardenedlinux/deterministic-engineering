;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; -*- Gerbil -*-
(import
  :clan/poo/object)
(export
  EvidencePolicy)
(.def EvidencePolicy
  result-kind: 'recorded-only
  closure: 'exact-required-inputs
  outcomes: '(pass fail))
