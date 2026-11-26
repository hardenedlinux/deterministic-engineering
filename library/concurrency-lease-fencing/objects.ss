;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Distributed Lease & Monotonic Fencing Token engineering model.
;;; Grounded in Kleppmann (2016), Burrows (Chubby, OSDI 2006), and Ongaro &
;;; Ousterhout (Raft, USENIX ATC 2014): emergent fencing safety (zero synthetic unsafe flag)
;;; with auto-derived countermodel via (guard ...).
(import :clan/poo/object
        (only-in "../threat-capabilities/objects.ss" ThreatModel.))
(export LeaseFencingModel
        StaleLeaseZombieWriteCountermodel)

(.def (LeaseFencingModel @ ThreatModel.)
  identity: 'engineering.concurrency.lease-fencing-token
  family: 'engineering.concurrency.lease-fencing-token
  quint-module: "lease_fencing_token"
  quint-file: "LeaseFencingToken.qnt"
  domain-dir: "engineering/concurrency/lease-fencing-token"
  quint-imports: '()
  rules: '((monotonic-fencing-token ENG-FENCE-MONO quint))
  dependencies: '((ENG-FENCE-MONO source) (ENG-FENCE-MONO profile) (ENG-FENCE-MONO method))
  invariant: "Storage only accepts writes whose fencing token is >= storageMaxToken, neutralizing zombie writes from paused lease holders."
  parameters: '()
  state: '((nextToken "int" "1")
           (c1Token "int" "0")
           (c1Paused "bool" "false")
           (c2Token "int" "0")
           (storageMaxToken "int" "0")
           (lastWriterToken "int" "0"))
  guards: '((monotonic-fencing-token (>= (. h c1Token) (. h storageMaxToken))))
  transitions:
  '((acquireC1
     (action acquireC1 ()
       (if (and (= (. h c1Token) 0) (<= (. h nextToken) 3))
         (set-h (c1Token (. h nextToken))
                (nextToken (+ (. h nextToken) 1))
                (c1Paused #f))
         (keep-h))))
    (pauseC1
     (action pauseC1 ()
       (if (and (> (. h c1Token) 0) (not (. h c1Paused)))
         (set-h (c1Paused #t))
         (keep-h))))
    (acquireC2
     (action acquireC2 ()
       (if (and (= (. h c2Token) 0) (<= (. h nextToken) 3))
         (set-h (c2Token (. h nextToken))
                (nextToken (+ (. h nextToken) 1)))
         (keep-h))))
    (writeC1
     (action writeC1 ()
       (if (> (. h c1Token) 0)
         (if (guard monotonic-fencing-token (>= (. h c1Token) (. h storageMaxToken)))
           (set-h (storageMaxToken (if (> (. h c1Token) (. h storageMaxToken)) (. h c1Token) (. h storageMaxToken)))
                  (lastWriterToken (. h c1Token))
                  (c1Paused #f))
           (set-h (c1Paused #f)))
         (keep-h))))
    (writeC2
     (action writeC2 ()
       (if (> (. h c2Token) 0)
         (if (>= (. h c2Token) (. h storageMaxToken))
           (set-h (storageMaxToken (. h c2Token))
                  (lastWriterToken (. h c2Token)))
           (keep-h))
         (keep-h))))
    (step
     (action step () (any acquireC1 pauseC1 acquireC2 writeC1 writeC2))))
  safety: '(>= (. h lastWriterToken) (. h storageMaxToken))
  traces:
  '((checkSafe (action checkSafe () (all (assert safety) (keep-h))))
    (checkUnsafe (action checkUnsafe () (all (assert (not safety)) (keep-h))))
    (staleC1WriteRejectedAfterC2Test
     (run staleC1WriteRejectedAfterC2Test
       (then init acquireC1 pauseC1 acquireC2 writeC2 writeC1
             (all (assert (= (. h storageMaxToken) 2))
                  (assert (= (. h lastWriterToken) 2))
                  (assert safety)
                  (keep-h)))))
    (zombieWriteCountermodelTest
     (run zombieWriteCountermodelTest
       (then init acquireC1 pauseC1 acquireC2 writeC2 writeC1NoFencing checkUnsafe))))
  countermodels: (list StaleLeaseZombieWriteCountermodel)
  limits: "Finite two-client lease and storage fencing abstraction; does not model physical clock drift, consensus quorum replication, or storage crash recovery.")

(.def (StaleLeaseZombieWriteCountermodel @ LeaseFencingModel)
  identity: 'engineering.concurrency.lease-fencing-token.stale-lease-zombie-write
  dropped-guard: 'monotonic-fencing-token
  step-action: "stepZombieWrite"
  derive-from-transition: 'writeC1
  derive-action-name: 'writeC1NoFencing
  expected-itf-predicate: "h.lastWriterToken < h.storageMaxToken")
