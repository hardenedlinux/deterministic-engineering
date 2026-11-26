;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Software Supply Chain TUF / Sigstore / in-toto Metadata Verification model.
;;; Co-located Yuanxu unit: single source of truth alongside SupplyChainTuf.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export SupplyChainTufModel
        TufRollbackCountermodel
        TufFreezeCountermodel
        TufMixAndMatchCountermodel)

(.def (SupplyChainTufModel @ AuthorityCurrentnessModel)
  identity: 'threat.supply-chain.supply-chain-tuf
  family: 'threat.supply-chain.supply-chain-tuf
  title: "Software Supply Chain TUF Rollback, Freeze & Mix-and-Match Defense"
  subdomain: 'quint.threat.supply-chain
  papers:
  '(("J. Samuel, N. Mathewson, J. Cappos & R. Dingledine (ACM CCS 2010)"
     "Survivable Key Compromise in Software Update Systems (The Update Framework / TUF).")
    ("S. Torres-Arias, H. Afzali, T. K. Kuppusamy, R. Curtmola & J. Cappos (USENIX Security 2019)"
     "in-toto: Providing farm-to-table guarantees for bits and bytes.")
    ("Z. Newman, J. S. Meyers & S. Torres-Arias (ACM CCS 2022)"
     "Sigstore: Software Signing for Everybody."))
  quint-module: "supply_chain_tuf"
  quint-file: "SupplyChainTuf.qnt"
  domain-dir: "threat/supply-chain/supply-chain-tuf"
  quint-imports:
  '(("authority_currentness" "../../zero-trust/authority-currentness/AuthorityCurrentness"))
  rules:
  '((monotonic-version-check TUF-MONO-VER quint)
    (timestamp-expiry-check TUF-TS-EXP quint)
    (snapshot-atomic-binding TUF-SNAP-BIND quint))
  dependencies:
  '((TUF-MONO-VER source)
    (TUF-MONO-VER profile)
    (TUF-MONO-VER method)
    (TUF-TS-EXP source)
    (TUF-TS-EXP profile)
    (TUF-TS-EXP method)
    (TUF-SNAP-BIND source)
    (TUF-SNAP-BIND profile)
    (TUF-SNAP-BIND method))
  invariant: "Client never installs a target older than its monotonic snapshot floor, never accepts expired timestamp metadata, and always binds artifact hash atomically to its snapshot."
  parameters: '()
  state:
  '((clock "int" "1")
    (repoVer "int" "1")
    (clientMinVer "int" "1")
    (installedVer "int" "1")
    (installedHash "int" "1")
    (installedSnapTargetVer "int" "1")
    (installedMetaExp "int" "2")
    (installedAtClock "int" "1"))
  guards:
  '((monotonic-version-check
      (and (>= tsVer (. h clientMinVer))
           (>= targetVer (. h installedVer))))
    (timestamp-expiry-check (>= tsExp (. h clock)))
    (snapshot-atomic-binding
      (and (= snapVer tsVer)
           (= targetVer snapVer)
           (= targetHash targetVer))))
  transitions:
  '((publishRelease
      (action publishRelease ()
        (if (< (. h repoVer) 3)
          (set-h (repoVer (+ (. h repoVer) 1)))
          (keep-h))))
    (advanceClock
      (action advanceClock ()
        (if (< (. h clock) 4)
          (set-h (clock (+ (. h clock) 1)))
          (keep-h))))
    (clientUpdateAs
      (action clientUpdateAs ((tsVer "int")
                              (tsExp "int")
                              (snapVer "int")
                              (targetVer "int")
                              (targetHash "int"))
              "bool"
        (if (and (>= tsVer 1)
                 (<= tsVer (. h repoVer))
                 (guard monotonic-version-check
                        (and (>= tsVer (. h clientMinVer))
                             (>= targetVer (. h installedVer))))
                 (guard timestamp-expiry-check (>= tsExp (. h clock)))
                 (guard snapshot-atomic-binding
                        (and (= snapVer tsVer)
                             (= targetVer snapVer)
                             (= targetHash targetVer))))
          (set-h (clientMinVer (if (> tsVer (. h clientMinVer))
                                 tsVer
                                 (. h clientMinVer)))
                 (installedVer targetVer)
                 (installedHash targetHash)
                 (installedSnapTargetVer snapVer)
                 (installedMetaExp tsExp)
                 (installedAtClock (. h clock)))
          (keep-h))))
    (clientUpdate
      (action clientUpdate ()
        (nondet ((v (set 1 2 3))
                 (t (set 1 2 3)))
          (call clientUpdateAs v (+ v 1) v t t))))
    (step
      (action step ()
        (any publishRelease advanceClock clientUpdate))))
  safety:
  '(and (>= (. h installedVer) (. h clientMinVer))
        (>= (. h installedMetaExp) (. h installedAtClock))
        (= (. h installedHash) (. h installedSnapTargetVer)))
  traces:
  '((checkSafe
      (action checkSafe ()
        (all (assert safety) (keep-h))))
    (checkUnsafe
      (action checkUnsafe ()
        (all (assert (not safety)) (keep-h))))
    (validUpgradeAndRejectRollbackTest
      (run validUpgradeAndRejectRollbackTest
        (then init publishRelease
              (call clientUpdateAs 2 3 2 2 2)
              (call clientUpdateAs 1 2 1 1 1)
              (all (assert (= (. h installedVer) 2))
                   (assert safety)
                   (keep-h)))))
    (expiredFreezeBlockedTest
      (run expiredFreezeBlockedTest
        (then init advanceClock advanceClock
              (call clientUpdateAs 1 2 1 1 1)
              (all (assert (= (. h installedAtClock) 1))
                   (assert safety)
                   (keep-h)))))
    (mixAndMatchBlockedTest
      (run mixAndMatchBlockedTest
        (then init publishRelease
              (call clientUpdateAs 2 3 2 1 1)
              (all (assert (= (. h installedVer) 1))
                   (assert (= (. h installedHash) (. h installedSnapTargetVer)))
                   (assert safety)
                   (keep-h)))))
    (rollbackCountermodelTest
      (run rollbackCountermodelTest
        (then init publishRelease
              (call clientUpdateAs 2 3 2 2 2)
              (call updateNoMonotonic 1 2 1 1 1)
              checkUnsafe))))
  countermodels:
  (list TufRollbackCountermodel
        TufFreezeCountermodel
        TufMixAndMatchCountermodel)
  limits: "Finite TUF 4-role metadata version/expiry/binding abstraction; does not model threshold key rotation ceremonies or Rekor Merkle inclusion proofs.")

(.def (TufRollbackCountermodel @ SupplyChainTufModel)
  identity: 'threat.supply-chain.supply-chain-tuf.rollback
  dropped-guard: 'monotonic-version-check
  step-action: "stepTufRollback"
  derive-from-transition: 'clientUpdateAs
  derive-action-name: 'updateNoMonotonic
  derive-step-call: '(nondet ((v (set 1 2 3)))
                       (call updateNoMonotonic v (+ v 1) v v v))
  expected-itf-predicate: "h.installedVer < h.clientMinVer")

(.def (TufFreezeCountermodel @ SupplyChainTufModel)
  identity: 'threat.supply-chain.supply-chain-tuf.freeze
  dropped-guard: 'timestamp-expiry-check
  step-action: "stepTufFreeze"
  derive-from-transition: 'clientUpdateAs
  derive-action-name: 'updateNoExpiry
  derive-step-call: '(nondet ((v (set 1 2 3)))
                       (call updateNoExpiry v (+ v 1) v v v))
  expected-itf-predicate: "h.installedMetaExp < h.installedAtClock")

(.def (TufMixAndMatchCountermodel @ SupplyChainTufModel)
  identity: 'threat.supply-chain.supply-chain-tuf.mix-and-match
  dropped-guard: 'snapshot-atomic-binding
  step-action: "stepTufMixAndMatch"
  derive-from-transition: 'clientUpdateAs
  derive-action-name: 'updateMixAndMatch
  derive-step-call: '(nondet ((v (set 1 2 3))
                              (hval (set 1 2 3)))
                       (call updateMixAndMatch v (+ v 1) v v hval))
  expected-itf-predicate: "h.installedHash != h.installedSnapTargetVer")
