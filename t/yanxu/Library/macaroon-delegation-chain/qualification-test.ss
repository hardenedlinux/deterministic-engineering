;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/macaroon-delegation-chain/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export macaroon-delegation-chain-qualification-test)

(def macaroon-delegation-chain-qualification-test
  (make-quint-model-qualification-suite
    "macaroon-delegation-chain"
    MacaroonDelegationModel
    (.get ThreatModelProfiles macaroon-delegation-chain)))
