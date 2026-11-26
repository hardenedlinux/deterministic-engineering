;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/storage-mvcc-ssi/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export storage-mvcc-ssi-qualification-test)

(def storage-mvcc-ssi-qualification-test
  (make-quint-model-qualification-suite
    "storage-mvcc-ssi"
    MvccSsiWriteSkewModel
    (.get ThreatModelProfiles storage-mvcc-ssi)))
