;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; -*- Gerbil -*-
(import
  :clan/poo/object)
(export
  ResourceLifecycleCase)
(.def ResourceLifecycleCase
  identity: 'resource-lifecycle
  library-key: 'rust.resources.backpressure-memory
  purpose: 'native-owner-protocol-review
  design: '("10.14" "10.15"))
