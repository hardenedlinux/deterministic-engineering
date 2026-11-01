;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; -*- Gerbil -*-
(import
  :clan/poo/object)
(export
  BackpressureReviewProfile)
;; Local, bounded coding-method review; class a exercises the NASA matrix.
;; This declaration is not an institutional NASA classification attestation.
(.def BackpressureReviewProfile
  identity: 'backpressure-coding-method/v1
  subject: "rust.backpressure-lifecycle"
  revision: "accepted-owner-slice/r1"
  scope: "bounded-permit-method/M01-M05"
  software-class: 'a
  target: 'worker-owned
  context: (.o
             safety-critical?: #f
             health-medical?: #f
             reaching-kdp-a?: #f
             category-1?: #f))
