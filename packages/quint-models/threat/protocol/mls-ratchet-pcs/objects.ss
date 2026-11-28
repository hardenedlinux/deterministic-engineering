;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; MLS (RFC 9420) / Double Ratchet Forward Secrecy, Post-Compromise Security (PCS) & Removal Exclusion.
;;; Co-located Yuanxu unit: single source of truth alongside MlsRatchetPcs.qnt and README.org.
;;; Models epoch-key zeroization (FS), fresh asymmetric entropy TreeKEM commit healing (PCS),
;;; and mandatory epoch-secret rotation on member removal.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export MlsRatchetPcsModel)

(.def (MlsRatchetPcsModel @ ThreatModel.)
  identity: 'threat.protocol.mls-ratchet-pcs
  family: 'threat.protocol.mls-ratchet-pcs
  title: "MLS (RFC 9420) / Double Ratchet Forward Secrecy & Post-Compromise Security"
  subdomain: 'quint.threat.protocol
  papers:
  '(("R. Barnes, B. Beurdouche, R. Robert, J. Millican, E. Omara & K. Cohn-Gordon (IETF RFC 9420, 2023)"
     "The Messaging Layer Security (MLS) Protocol: TreeKEM epoch key schedule, forward secrecy, and post-compromise security.")
    ("J. Alwen, S. Coretti, Y. Dodis & Y. Tselekounis (CRYPTO 2020)"
     "Security Analysis and Improvements for the IETF MLS Standard for Group Messaging.")
    ("K. Cohn-Gordon, C. Cremers, B. Dowling, L. Garratt & D. Stebila (IEEE EuroS&P 2017 / JoC 2020)"
     "A Formal Security Analysis of the Signal Messaging Protocol (Double Ratchet FS & PCS)."))
  quint-module: "mls_ratchet_pcs"
  quint-file: "MlsRatchetPcs.qnt"
  domain-dir: "threat/protocol/mls-ratchet-pcs"
  rules:
  '((ratchet-zeroize-old-key MLS-FS-ZEROIZE quint)
    (ratchet-fresh-entropy MLS-PCS-ENTROPY quint)
    (commit-rotate-on-remove MLS-REMOVE-ROTATE quint))
  dependencies:
  '((MLS-FS-ZEROIZE source)
    (MLS-FS-ZEROIZE profile)
    (MLS-FS-ZEROIZE method)
    (MLS-PCS-ENTROPY source)
    (MLS-PCS-ENTROPY profile)
    (MLS-PCS-ENTROPY method)
    (MLS-REMOVE-ROTATE source)
    (MLS-REMOVE-ROTATE profile)
    (MLS-REMOVE-ROTATE method))
  invariant: "A later state compromise never decrypts past epoch messages (Forward Secrecy), an honest fresh-entropy ratchet heals confidentiality after compromise (PCS), and a removed member never decrypts post-removal epoch messages."
  limits: "Symbolic Dolev-Yao abstraction of MLS (RFC 9420) / Double Ratchet epoch key evolution, zeroization, fresh-entropy healing, and removal rotation; does not model TreeKEM blank-node path compression, active delivery-service fork attacks, or IND-CCA KEM assumptions.")
