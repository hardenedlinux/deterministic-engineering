;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Distributed Lease & Monotonic Fencing Token engineering model.
;;; Co-located Yuanxu unit: single source of truth alongside LeaseFencingToken.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export LeaseFencingModel)

(.def (LeaseFencingModel @ ThreatModel.)
  identity: 'engineering.concurrency.lease-fencing-token
  family: 'engineering.concurrency.lease-fencing-token
  title: "Distributed Lease Expiry & Monotonic Fencing Tokens"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("M. Kleppmann (2016)"
     "How to Do Distributed Locking: monotonic fencing tokens neutralizing GC-paused zombie writers.")
    ("M. Burrows (USENIX OSDI 2006)"
     "The Chubby Lock Service for Loosely-Coupled Distributed Systems: sequencer tokens across lease renewals.")
    ("D. Ongaro & J. Ousterhout (USENIX ATC 2014)"
     "Raft consensus term numbers as monotonic leadership epochs."))
  quint-module: "lease_fencing_token"
  quint-file: "LeaseFencingToken.qnt"
  domain-dir: "engineering/concurrency/lease-fencing-token"
  rules:
  '((monotonic-fencing-token ENG-FENCE-MONO quint))
  dependencies:
  '((ENG-FENCE-MONO source)
    (ENG-FENCE-MONO profile)
    (ENG-FENCE-MONO method))
  invariant: "Storage only accepts writes whose fencing token is >= storageMaxToken, neutralizing zombie writes from paused lease holders."
  limits: "Finite two-client lease and storage fencing abstraction; does not model physical clock drift, consensus quorum replication, or storage crash recovery.")
