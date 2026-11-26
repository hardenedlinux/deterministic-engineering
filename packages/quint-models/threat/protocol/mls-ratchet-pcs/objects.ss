;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; MLS (RFC 9420) / Double Ratchet Forward Secrecy, Post-Compromise Security (PCS) & Removal Exclusion.
;;; Co-located Yuanxu unit: single source of truth alongside MlsRatchetPcs.qnt and README.org.
;;; Models epoch-key zeroization (FS), fresh asymmetric entropy TreeKEM commit healing (PCS),
;;; and mandatory epoch-secret rotation on member removal.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export MlsRatchetPcsModel
        MlsRetainOldKeyCountermodel
        MlsNoFreshEntropyPcsCountermodel
        MlsRemoveWithoutRotateCountermodel)

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
  quint-imports: '()
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
  parameters: '()
  state:
  '((epoch "int" "1")
    (keyGen "int" "1")
    (pastMsgSent "bool" "false")
    (pastMsgKeyGen "int" "0")
    (pastKeyRetained "bool" "false")
    (compromised "bool" "false")
    (attackerKeyGen "int" "0")
    (healed "bool" "false")
    (postHealMsgSent "bool" "false")
    (postHealMsgKeyGen "int" "0")
    (bobRemoved "bool" "false")
    (bobKeyGen "int" "1")
    (postRemoveMsgSent "bool" "false")
    (postRemoveMsgKeyGen "int" "0")
    (pastMsgDecrypted "bool" "false")
    (postHealMsgDecrypted "bool" "false")
    (removedMemberDecrypted "bool" "false"))
  guards:
  '((ratchet-zeroize-old-key (not (. h pastKeyRetained)))
    (ratchet-fresh-entropy (> (. h keyGen) (. h attackerKeyGen)))
    (commit-rotate-on-remove (> (. h keyGen) (. h bobKeyGen))))
  transitions:
  '((sendPastMessage
      (action sendPastMessage ()
        (if (and (= (. h epoch) 1) (not (. h pastMsgSent)))
          (set-h (pastMsgSent #t)
                 (pastMsgKeyGen (. h keyGen)))
          (keep-h))))
    (advanceEpochRegular
      (action advanceEpochRegular ()
        (if (and (< (. h epoch) 5) (. h pastMsgSent) (not (. h compromised)))
          (set-h (epoch (+ (. h epoch) 1))
                 (keyGen (+ (. h keyGen) 1))
                 (bobKeyGen (if (. h bobRemoved) (. h bobKeyGen) (+ (. h keyGen) 1)))
                 (pastKeyRetained (guard ratchet-zeroize-old-key #f #t)))
          (keep-h))))
    (compromiseCurrentState
      (action compromiseCurrentState ()
        (if (and (>= (. h epoch) 2) (not (. h compromised)))
          (set-h (compromised #t)
                 (attackerKeyGen (. h keyGen)))
          (keep-h))))
    (ratchetHealPcs
      (action ratchetHealPcs ()
        (if (and (. h compromised) (not (. h healed)) (< (. h epoch) 5))
          (set-h (epoch (+ (. h epoch) 1))
                 (healed #t)
                 (keyGen (guard ratchet-fresh-entropy (+ (. h keyGen) 1) (. h keyGen)))
                 (bobKeyGen (if (. h bobRemoved)
                              (. h bobKeyGen)
                              (guard ratchet-fresh-entropy (+ (. h keyGen) 1) (. h keyGen)))))
          (keep-h))))
    (sendPostHealMessage
      (action sendPostHealMessage ()
        (if (and (. h healed) (not (. h postHealMsgSent)))
          (set-h (postHealMsgSent #t)
                 (postHealMsgKeyGen (. h keyGen)))
          (keep-h))))
    (removeBobCommit
      (action removeBobCommit ()
        (if (and (not (. h bobRemoved)) (< (. h epoch) 5))
          (set-h (epoch (+ (. h epoch) 1))
                 (bobRemoved #t)
                 (keyGen (guard commit-rotate-on-remove (+ (. h keyGen) 1) (. h keyGen))))
          (keep-h))))
    (sendPostRemoveMessage
      (action sendPostRemoveMessage ()
        (if (and (. h bobRemoved) (not (. h postRemoveMsgSent)))
          (set-h (postRemoveMsgSent #t)
                 (postRemoveMsgKeyGen (. h keyGen)))
          (keep-h))))
    (attackerDecryptPast
      (action attackerDecryptPast ()
        (if (and (. h compromised)
                 (. h pastMsgSent)
                 (or (= (. h attackerKeyGen) (. h pastMsgKeyGen))
                     (. h pastKeyRetained)))
          (set-h (pastMsgDecrypted #t))
          (keep-h))))
    (attackerDecryptPostHeal
      (action attackerDecryptPostHeal ()
        (if (and (. h compromised)
                 (. h postHealMsgSent)
                 (= (. h attackerKeyGen) (. h postHealMsgKeyGen)))
          (set-h (postHealMsgDecrypted #t))
          (keep-h))))
    (bobDecryptPostRemove
      (action bobDecryptPostRemove ()
        (if (and (. h bobRemoved)
                 (. h postRemoveMsgSent)
                 (= (. h bobKeyGen) (. h postRemoveMsgKeyGen)))
          (set-h (removedMemberDecrypted #t))
          (keep-h))))
    (step
      (action step ()
        (any sendPastMessage advanceEpochRegular compromiseCurrentState
             ratchetHealPcs sendPostHealMessage removeBobCommit sendPostRemoveMessage
             attackerDecryptPast attackerDecryptPostHeal bobDecryptPostRemove))))
  safety:
  '(and (not (. h pastMsgDecrypted))
        (not (. h postHealMsgDecrypted))
        (not (. h removedMemberDecrypted)))
  traces:
  '((checkSafe
      (action checkSafe ()
        (all (assert safety) (keep-h))))
    (checkUnsafe
      (action checkUnsafe ()
        (all (assert (not safety)) (keep-h))))
    (fullFsPcsAndRemovalLifecycleTest
      (run fullFsPcsAndRemovalLifecycleTest
        (then init
              sendPastMessage
              advanceEpochRegular
              compromiseCurrentState
              attackerDecryptPast
              ratchetHealPcs
              sendPostHealMessage
              attackerDecryptPostHeal
              removeBobCommit
              sendPostRemoveMessage
              bobDecryptPostRemove
              (all (assert (. h pastMsgSent))
                   (assert (. h postHealMsgSent))
                   (assert (. h postRemoveMsgSent))
                   (assert safety)
                   (keep-h)))))
    (retainOldKeyBreaksFsCountermodelTest
      (run retainOldKeyBreaksFsCountermodelTest
        (then init
              sendPastMessage
              advanceEpochRetainOldKey
              compromiseCurrentState
              attackerDecryptPast
              checkUnsafe)))
    (noFreshEntropyBreaksPcsCountermodelTest
      (run noFreshEntropyBreaksPcsCountermodelTest
        (then init
              sendPastMessage
              advanceEpochRegular
              compromiseCurrentState
              ratchetHealNoEntropy
              sendPostHealMessage
              attackerDecryptPostHeal
              checkUnsafe)))
    (removeWithoutRotateCountermodelTest
      (run removeWithoutRotateCountermodelTest
        (then init
              removeBobNoRotate
              sendPostRemoveMessage
              bobDecryptPostRemove
              checkUnsafe))))
  countermodels:
  (list MlsRetainOldKeyCountermodel
        MlsNoFreshEntropyPcsCountermodel
        MlsRemoveWithoutRotateCountermodel)
  limits: "Symbolic Dolev-Yao abstraction of MLS (RFC 9420) / Double Ratchet epoch key evolution, zeroization, fresh-entropy healing, and removal rotation; does not model TreeKEM blank-node path compression, active delivery-service fork attacks, or IND-CCA KEM assumptions.")

(.def (MlsRetainOldKeyCountermodel @ MlsRatchetPcsModel)
  identity: 'threat.protocol.mls-ratchet-pcs.retain-old-key
  dropped-guard: 'ratchet-zeroize-old-key
  step-action: "stepRetainOldKey"
  derive-from-transition: 'advanceEpochRegular
  derive-action-name: 'advanceEpochRetainOldKey
  expected-itf-predicate: "h.pastMsgDecrypted == true and h.pastKeyRetained == true")

(.def (MlsNoFreshEntropyPcsCountermodel @ MlsRatchetPcsModel)
  identity: 'threat.protocol.mls-ratchet-pcs.no-fresh-entropy-pcs
  dropped-guard: 'ratchet-fresh-entropy
  step-action: "stepNoFreshEntropyPcs"
  derive-from-transition: 'ratchetHealPcs
  derive-action-name: 'ratchetHealNoEntropy
  expected-itf-predicate: "h.postHealMsgDecrypted == true and h.healed == true")

(.def (MlsRemoveWithoutRotateCountermodel @ MlsRatchetPcsModel)
  identity: 'threat.protocol.mls-ratchet-pcs.remove-without-rotate
  dropped-guard: 'commit-rotate-on-remove
  step-action: "stepRemoveWithoutRotate"
  derive-from-transition: 'removeBobCommit
  derive-action-name: 'removeBobNoRotate
  expected-itf-predicate: "h.removedMemberDecrypted == true and h.bobRemoved == true")
