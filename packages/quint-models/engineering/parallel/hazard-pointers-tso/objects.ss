;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Hazard Pointers under x86-TSO Store-Buffer Reordering engineering model.
;;; Co-located Yuanxu unit: single source of truth alongside HazardPointersTso.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export HazardPointersTsoModel
        MissingTsoFenceUafCountermodel)

(.def (HazardPointersTsoModel @ ThreatModel.)
  identity: 'engineering.parallel.hazard-pointers-tso
  family: 'engineering.parallel.hazard-pointers-tso
  title: "Hazard Pointers under x86-TSO Store-Buffer Reordering"
  subdomain: 'quint.engineering.parallel
  papers:
  '(("M. M. Michael (IEEE TPDS 2004)"
     "Hazard Pointers: Safe Memory Reclamation for Lock-Free Objects — publish-then-validate protocol.")
    ("P. Sewell, S. Sarkar, S. Owens, F. Zappa Nardelli & M. O. Myreen (CACM 2010)"
     "x86-TSO: A Rigorous and Usable Programmer's Model for x86 Multiprocessors — store-load buffering and MFENCE."))
  quint-module: "hazard_pointers_tso"
  quint-file: "HazardPointersTso.qnt"
  domain-dir: "engineering/parallel/hazard-pointers-tso"
  quint-imports: '()
  countermodel-depth: 9
  rules:
  '((tso-store-load-fence PAR-HP-TSO-FENCE quint))
  dependencies:
  '((PAR-HP-TSO-FENCE source)
    (PAR-HP-TSO-FENCE profile)
    (PAR-HP-TSO-FENCE method))
  invariant: "A reader thread never dereferences a node that the reclaimer has already freed (zero Use-After-Free under x86-TSO store-buffer reordering)."
  parameters: '()
  state:
  '((nodePublished "bool" "true")
    (nodeRetired "bool" "false")
    (nodeFreed "bool" "false")
    (readerPc "int" "0")
    (readerHpBuffered "bool" "false")
    (readerHpVisible "bool" "false")
    (reclaimerScanned "bool" "false")
    (reclaimerSawHp "bool" "false"))
  guards:
  '((tso-store-load-fence (= (. h readerPc) 2)))
  transitions:
  '((readerLoadPtr
      (action readerLoadPtr ()
        (if (and (= (. h readerPc) 0) (. h nodePublished))
          (set-h (readerPc 1))
          (keep-h))))
    (readerStoreHp
      (action readerStoreHp ()
        (if (= (. h readerPc) 1)
          (set-h (readerPc 2)
                 (readerHpBuffered #t))
          (keep-h))))
    (tsoFlushHp
      (action tsoFlushHp ()
        (if (and (. h readerHpBuffered) (not (. h readerHpVisible)))
          (set-h (readerHpVisible #t))
          (keep-h))))
    (readerMfence
      (action readerMfence ()
        (if (= (. h readerPc) 2)
          (set-h (readerPc 3)
                 (readerHpVisible (guard tso-store-load-fence
                                         #t
                                         (. h readerHpVisible))))
          (keep-h))))
    (readerValidate
      (action readerValidate ()
        (if (= (. h readerPc) 3)
          (if (. h nodePublished)
            (set-h (readerPc 4))
            (set-h (readerPc 0)
                   (readerHpBuffered #f)
                   (readerHpVisible #f)))
          (keep-h))))
    (readerDeref
      (action readerDeref ()
        (if (= (. h readerPc) 4)
          (set-h (readerPc 5))
          (keep-h))))
    (reclaimerRetire
      (action reclaimerRetire ()
        (if (and (. h nodePublished) (not (. h nodeRetired)))
          (set-h (nodePublished #f)
                 (nodeRetired #t))
          (keep-h))))
    (reclaimerScan
      (action reclaimerScan ()
        (if (and (. h nodeRetired) (not (. h reclaimerScanned)))
          (set-h (reclaimerScanned #t)
                 (reclaimerSawHp (. h readerHpVisible)))
          (keep-h))))
    (reclaimerFree
      (action reclaimerFree ()
        (if (and (. h reclaimerScanned)
                 (not (. h reclaimerSawHp))
                 (not (. h nodeFreed)))
          (set-h (nodeFreed #t))
          (keep-h))))
    (step
      (action step ()
        (any readerLoadPtr readerStoreHp tsoFlushHp readerMfence readerValidate readerDeref
             reclaimerRetire reclaimerScan reclaimerFree))))
  safety: '(not (and (= (. h readerPc) 5) (. h nodeFreed)))
  traces:
  '((checkSafe
      (action checkSafe ()
        (all (assert safety) (keep-h))))
    (checkUnsafe
      (action checkUnsafe ()
        (all (assert (not safety)) (keep-h))))
    (fencedHpBlocksFreeTest
      (run fencedHpBlocksFreeTest
        (then init readerLoadPtr readerStoreHp readerMfence
              reclaimerRetire reclaimerScan reclaimerFree
              (all (assert (not (. h nodeFreed)))
                   (assert safety)
                   (keep-h)))))
    (retireBeforeValidateRetriesSafelyTest
      (run retireBeforeValidateRetriesSafelyTest
        (then init readerLoadPtr readerStoreHp readerMfence
              reclaimerRetire readerValidate
              (all (assert (= (. h readerPc) 0))
                   (assert safety)
                   (keep-h)))))
    (tsoMissingFenceUafCountermodelTest
      (run tsoMissingFenceUafCountermodelTest
        (then init readerLoadPtr readerStoreHp readerSkipMfence readerValidate
              reclaimerRetire reclaimerScan reclaimerFree readerDeref checkUnsafe))))
  countermodels: (list MissingTsoFenceUafCountermodel)
  limits: "Finite single-node, single-reader, single-reclaimer x86-TSO store-buffer abstraction; does not model ARM/POWER non-multi-copy-atomic reordering or dynamic HP array resizing.")

(.def (MissingTsoFenceUafCountermodel @ HazardPointersTsoModel)
  identity: 'engineering.parallel.hazard-pointers-tso.missing-tso-fence-uaf
  dropped-guard: 'tso-store-load-fence
  step-action: "stepMissingTsoFence"
  derive-from-transition: 'readerMfence
  derive-action-name: 'readerSkipMfence
  expected-itf-predicate: "h.readerPc == 5 and h.nodeFreed == true")
