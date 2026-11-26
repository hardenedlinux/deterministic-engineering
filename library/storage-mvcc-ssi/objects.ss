;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Distributed MVCC & Serializable Snapshot Isolation (SSI) Write-Skew engineering model.
;;; Grounded in Berenson et al. (ACM SIGMOD 1995, Snapshot Isolation & Write Skew A5B),
;;; Adya, Liskov & O'Neil (ICDE 2000, DSG rw-antidependency cycles),
;;; Cahill, Rohm & Fekete (ACM SIGMOD 2008 / TODS 2009, SIREAD & dangerous structures),
;;; and Ports & Grittner (PVLDB 2012, PostgreSQL SSI persistent SIREAD & read-time rw detection).
;;; Emergent multi-row business invariant + conservation law (zero synthetic unsafe flag);
;;; all 3 classic isolation counterexamples are auto-derived via (guard ...).
(import :clan/poo/object
        (only-in "../threat-capabilities/objects.ss" ThreatModel.))
(export MvccSsiWriteSkewModel
        SnapshotIsolationWriteSkewCountermodel
        EarlySireadReleaseCountermodel
        MissedReadRwConflictCountermodel)

(.def (MvccSsiWriteSkewModel @ ThreatModel.)
  identity: 'engineering.storage.mvcc-ssi-write-skew
  family: 'engineering.storage.mvcc-ssi-write-skew
  quint-module: "storage_mvcc_ssi"
  quint-file: "MvccSsiWriteSkew.qnt"
  domain-dir: "engineering/storage/mvcc-ssi-write-skew"
  quint-imports: '()
  verify-depth: 10
  countermodel-depth: 9
  rules: '((ssi-dangerous-structure STOR-MVCC-SSI quint)
           (retain-siread-after-commit STOR-MVCC-SIREAD quint)
           (detect-rw-on-read STOR-MVCC-READRW quint))
  dependencies: '((STOR-MVCC-SSI source) (STOR-MVCC-SSI profile) (STOR-MVCC-SSI method)
                  (STOR-MVCC-SIREAD source) (STOR-MVCC-SIREAD profile) (STOR-MVCC-SIREAD method)
                  (STOR-MVCC-READRW source) (STOR-MVCC-READRW profile) (STOR-MVCC-READRW method))
  invariant: "Serializable Snapshot Isolation preserves the multi-key invariant (balX + balY >= 1) and withdrawal conservation (balX + balY + committedWithdrawals == 2) across all concurrent schedules."
  parameters: '()
  state: '((balX "int" "1")
           (balY "int" "1")
           (commitSeq "int" "1")
           (xModSeq "int" "1")
           (yModSeq "int" "1")
           (committedWithdrawals "int" "0")
           (t1State "int" "0")
           (t1Snap "int" "0")
           (t1SnapX "int" "0")
           (t1SnapY "int" "0")
           (t1SireadX "bool" "false")
           (t1SireadY "bool" "false")
           (t1WriteKey "int" "0")
           (t1CommitSeq "int" "0")
           (t1InRw "bool" "false")
           (t1OutRw "bool" "false")
           (t2State "int" "0")
           (t2Snap "int" "0")
           (t2SnapX "int" "0")
           (t2SnapY "int" "0")
           (t2SireadX "bool" "false")
           (t2SireadY "bool" "false")
           (t2WriteKey "int" "0")
           (t2CommitSeq "int" "0")
           (t2InRw "bool" "false")
           (t2OutRw "bool" "false"))
  guards: '((ssi-dangerous-structure (not (or (and txInRw txOutRw) (and otherCommitted otherInRw otherOutRw))))
            (retain-siread-after-commit (. h t1SireadX))
            (detect-rw-on-read (or otherActiveWrite otherCommittedOverwrote)))
  transitions:
  '((beginTxAs
      (action beginTxAs ((tx "int")) "bool"
        (if (= tx 1)
          (if (= (. h t1State) 0)
            (set-h (t1State 1) (t1Snap (. h commitSeq)) (t1SnapX (. h balX)) (t1SnapY (. h balY)))
            (keep-h))
          (if (= (. h t2State) 0)
            (set-h (t2State 1) (t2Snap (. h commitSeq)) (t2SnapX (. h balX)) (t2SnapY (. h balY)))
            (keep-h)))))
    (beginTx
      (action beginTx ()
        (nondet ((tx (set 1 2)))
          (call beginTxAs tx))))
    (readBothAs
      (action readBothAs ((tx "int")) "bool"
        (if (= tx 1)
          (if (and (= (. h t1State) 1) (not (. h t1SireadX)))
            (set-h
              (t1SireadX #t)
              (t1SireadY #t)
              (t1OutRw (or (. h t1OutRw)
                           (guard detect-rw-on-read
                                  (or (and (= (. h t2State) 1) (> (. h t2WriteKey) 0))
                                      (and (= (. h t2State) 2) (> (. h t2CommitSeq) (. h t1Snap))))
                                  #f)))
              (t2InRw (or (. h t2InRw)
                          (guard detect-rw-on-read
                                 (or (and (= (. h t2State) 1) (> (. h t2WriteKey) 0))
                                     (and (= (. h t2State) 2) (> (. h t2CommitSeq) (. h t1Snap))))
                                 #f))))
            (keep-h))
          (if (and (= (. h t2State) 1) (not (. h t2SireadX)))
            (set-h
              (t2SireadX #t)
              (t2SireadY #t)
              (t2OutRw (or (. h t2OutRw)
                           (guard detect-rw-on-read
                                  (or (and (= (. h t1State) 1) (> (. h t1WriteKey) 0))
                                      (and (= (. h t1State) 2) (> (. h t1CommitSeq) (. h t2Snap))))
                                  #f)))
              (t1InRw (or (. h t1InRw)
                          (guard detect-rw-on-read
                                 (or (and (= (. h t1State) 1) (> (. h t1WriteKey) 0))
                                     (and (= (. h t1State) 2) (> (. h t1CommitSeq) (. h t2Snap))))
                                 #f))))
            (keep-h)))))
    (readBoth
      (action readBoth ()
        (nondet ((tx (set 1 2)))
          (call readBothAs tx))))
    (writeWithdrawAs
      (action writeWithdrawAs ((tx "int") (key "int")) "bool"
        (if (= tx 1)
          (if (and (= (. h t1State) 1)
                   (. h t1SireadX)
                   (. h t1SireadY)
                   (= (. h t1WriteKey) 0)
                   (>= (+ (. h t1SnapX) (. h t1SnapY)) 2)
                   (or (and (= key 1) (>= (. h t1SnapX) 1))
                       (and (= key 2) (>= (. h t1SnapY) 1))))
            (set-h
              (t1WriteKey key)
              (t2OutRw (or (. h t2OutRw)
                           (and (or (= (. h t2State) 1) (= (. h t2State) 2))
                                (or (and (= key 1) (. h t2SireadX))
                                    (and (= key 2) (. h t2SireadY))))))
              (t1InRw (or (. h t1InRw)
                          (and (or (= (. h t2State) 1) (= (. h t2State) 2))
                               (or (and (= key 1) (. h t2SireadX))
                                   (and (= key 2) (. h t2SireadY)))))))
            (keep-h))
          (if (and (= (. h t2State) 1)
                   (. h t2SireadX)
                   (. h t2SireadY)
                   (= (. h t2WriteKey) 0)
                   (>= (+ (. h t2SnapX) (. h t2SnapY)) 2)
                   (or (and (= key 1) (>= (. h t2SnapX) 1))
                       (and (= key 2) (>= (. h t2SnapY) 1))))
            (set-h
              (t2WriteKey key)
              (t1OutRw (or (. h t1OutRw)
                           (and (or (= (. h t1State) 1) (= (. h t1State) 2))
                                (or (and (= key 1) (. h t1SireadX))
                                    (and (= key 2) (. h t1SireadY))))))
              (t2InRw (or (. h t2InRw)
                          (and (or (= (. h t1State) 1) (= (. h t1State) 2))
                               (or (and (= key 1) (. h t1SireadX))
                                   (and (= key 2) (. h t1SireadY)))))))
            (keep-h)))))
    (writeWithdraw
      (action writeWithdraw ()
        (nondet ((tx (set 1 2)) (key (set 1 2)))
          (call writeWithdrawAs tx key))))
    (commitTxAs
      (action commitTxAs ((tx "int")) "bool"
        (if (= tx 1)
          (if (and (= (. h t1State) 1) (> (. h t1WriteKey) 0))
            (if (and (not (and (= (. h t1WriteKey) 1) (> (. h xModSeq) (. h t1Snap))))
                     (not (and (= (. h t1WriteKey) 2) (> (. h yModSeq) (. h t1Snap))))
                     (guard ssi-dangerous-structure
                            (not (or (and (. h t1InRw) (. h t1OutRw))
                                     (and (= (. h t2State) 2) (. h t2InRw) (. h t2OutRw))))))
              (set-h
                (t1State 2)
                (commitSeq (+ (. h commitSeq) 1))
                (t1CommitSeq (+ (. h commitSeq) 1))
                (balX (if (= (. h t1WriteKey) 1) (- (. h balX) 1) (. h balX)))
                (balY (if (= (. h t1WriteKey) 2) (- (. h balY) 1) (. h balY)))
                (xModSeq (if (= (. h t1WriteKey) 1) (+ (. h commitSeq) 1) (. h xModSeq)))
                (yModSeq (if (= (. h t1WriteKey) 2) (+ (. h commitSeq) 1) (. h yModSeq)))
                (committedWithdrawals (+ (. h committedWithdrawals) 1))
                (t1SireadX (guard retain-siread-after-commit (. h t1SireadX) #f))
                (t1SireadY (guard retain-siread-after-commit (. h t1SireadY) #f)))
              (set-h (t1State 3) (t1SireadX #f) (t1SireadY #f)))
            (keep-h))
          (if (and (= (. h t2State) 1) (> (. h t2WriteKey) 0))
            (if (and (not (and (= (. h t2WriteKey) 1) (> (. h xModSeq) (. h t2Snap))))
                     (not (and (= (. h t2WriteKey) 2) (> (. h yModSeq) (. h t2Snap))))
                     (guard ssi-dangerous-structure
                            (not (or (and (. h t2InRw) (. h t2OutRw))
                                     (and (= (. h t1State) 2) (. h t1InRw) (. h t1OutRw))))))
              (set-h
                (t2State 2)
                (commitSeq (+ (. h commitSeq) 1))
                (t2CommitSeq (+ (. h commitSeq) 1))
                (balX (if (= (. h t2WriteKey) 1) (- (. h balX) 1) (. h balX)))
                (balY (if (= (. h t2WriteKey) 2) (- (. h balY) 1) (. h balY)))
                (xModSeq (if (= (. h t2WriteKey) 1) (+ (. h commitSeq) 1) (. h xModSeq)))
                (yModSeq (if (= (. h t2WriteKey) 2) (+ (. h commitSeq) 1) (. h yModSeq)))
                (committedWithdrawals (+ (. h committedWithdrawals) 1))
                (t2SireadX (guard retain-siread-after-commit (. h t2SireadX) #f))
                (t2SireadY (guard retain-siread-after-commit (. h t2SireadY) #f)))
              (set-h (t2State 3) (t2SireadX #f) (t2SireadY #f)))
            (keep-h)))))
    (commitTx
      (action commitTx ()
        (nondet ((tx (set 1 2)))
          (call commitTxAs tx))))
    (step
      (action step ()
        (any beginTx readBoth writeWithdraw commitTx))))
  safety:
  '(and (>= (+ (. h balX) (. h balY)) 1)
        (= (+ (+ (. h balX) (. h balY)) (. h committedWithdrawals)) 2))
  traces:
  '((checkSafe (action checkSafe () (all (assert safety) (keep-h))))
    (checkUnsafe (action checkUnsafe () (all (assert (not safety)) (keep-h))))
    (ssiBlocksWriteSkewTest
      (run ssiBlocksWriteSkewTest
        (then init (call beginTxAs 1) (call beginTxAs 2)
              (call readBothAs 1) (call readBothAs 2)
              (call writeWithdrawAs 1 1) (call commitTxAs 1)
              (call writeWithdrawAs 2 2) (call commitTxAs 2)
              (all (assert (= (. h t1State) 2))
                   (assert (= (. h t2State) 3))
                   (assert (= (+ (. h balX) (. h balY)) 1))
                   (assert safety)
                   (keep-h)))))
    (siWriteSkewCountermodelTest
      (run siWriteSkewCountermodelTest
        (then init (call beginTxAs 1) (call beginTxAs 2)
              (call readBothAs 1) (call readBothAs 2)
              (call writeWithdrawAs 1 1) (call commitTxAs 1)
              (call writeWithdrawAs 2 2) (call commitTxNoSsi 2)
              checkUnsafe)))
    (earlySireadReleaseCountermodelTest
      (run earlySireadReleaseCountermodelTest
        (then init (call beginTxAs 1) (call beginTxAs 2)
              (call readBothAs 1) (call readBothAs 2)
              (call writeWithdrawAs 1 1) (call commitTxReleaseSiread 1)
              (call writeWithdrawAs 2 2) (call commitTxAs 2)
              checkUnsafe)))
    (missedReadRwCountermodelTest
      (run missedReadRwCountermodelTest
        (then init (call beginTxAs 1) (call beginTxAs 2)
              (call readBothAs 1) (call writeWithdrawAs 1 1) (call commitTxAs 1)
              (call readBothNoRwCheck 2)
              (call writeWithdrawAs 2 2) (call commitTxAs 2)
              checkUnsafe))))
  countermodels:
  (list SnapshotIsolationWriteSkewCountermodel
        EarlySireadReleaseCountermodel
        MissedReadRwConflictCountermodel)
  limits: "Finite 2-transaction, 2-key MVCC/SSI abstraction verifying write skew, lost updates, persistent SIREAD locks, and read-time rw-antidependencies; does not model 3-txn read-only anomalies, predicate index page coarsening, or GC vacuuming of old SIREAD locks.")

(.def (SnapshotIsolationWriteSkewCountermodel @ MvccSsiWriteSkewModel)
  identity: 'engineering.storage.mvcc-ssi-write-skew.snapshot-isolation-write-skew
  dropped-guard: 'ssi-dangerous-structure
  step-action: "stepSnapshotIsolation"
  derive-from-transition: 'commitTxAs
  derive-action-name: 'commitTxNoSsi
  derive-step-call: '(nondet ((tx (set 1 2))) (call commitTxNoSsi tx))
  expected-itf-predicate: "h.balX + h.balY == 0 and h.committedWithdrawals == 2")

(.def (EarlySireadReleaseCountermodel @ MvccSsiWriteSkewModel)
  identity: 'engineering.storage.mvcc-ssi-write-skew.early-siread-release
  dropped-guard: 'retain-siread-after-commit
  step-action: "stepEarlySireadRelease"
  derive-from-transition: 'commitTxAs
  derive-action-name: 'commitTxReleaseSiread
  derive-step-call: '(nondet ((tx (set 1 2))) (call commitTxReleaseSiread tx))
  expected-itf-predicate: "h.balX + h.balY == 0 and h.committedWithdrawals == 2")

(.def (MissedReadRwConflictCountermodel @ MvccSsiWriteSkewModel)
  identity: 'engineering.storage.mvcc-ssi-write-skew.missed-read-rw-conflict
  dropped-guard: 'detect-rw-on-read
  step-action: "stepMissedReadRw"
  derive-from-transition: 'readBothAs
  derive-action-name: 'readBothNoRwCheck
  derive-step-call: '(nondet ((tx (set 1 2))) (call readBothNoRwCheck tx))
  expected-itf-predicate: "h.balX + h.balY == 0 and h.committedWithdrawals == 2")
