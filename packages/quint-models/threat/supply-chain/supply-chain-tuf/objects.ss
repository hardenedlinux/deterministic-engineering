;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Software Supply Chain TUF / Sigstore / in-toto Metadata Verification model.
;;; Co-located Yuanxu unit: single source of truth alongside SupplyChainTuf.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export SupplyChainTufModel)

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
  limits: "Finite TUF 4-role metadata version/expiry/binding abstraction; does not model threshold key rotation ceremonies or Rekor Merkle inclusion proofs.")
