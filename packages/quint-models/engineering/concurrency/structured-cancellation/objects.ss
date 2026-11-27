;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Structured concurrency cancellation & child-drain quiescence model.
;;; Co-located Yuanxu unit: single source of truth alongside StructuredCancellation.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export StructuredCancelModel)

(.def (StructuredCancelModel @ ThreatModel.)
  identity: 'engineering.concurrency.structured-cancellation
  family: 'engineering.concurrency.structured-cancellation
  title: "Structured Concurrency Cancellation & Child Quiescence"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("N. J. Smith (2018)"
     "Notes on Structured Concurrency, or: Go Statement Considered Harmful — nursery lifetime & child-drain join barriers.")
    ("R. Pressler (OpenJDK JEP 453 / 480)"
     "Structured Concurrency: bounding child task lifetimes to lexical parent scopes."))
  quint-module: "concurrency_structured_cancel"
  quint-file: "StructuredCancellation.qnt"
  domain-dir: "engineering/concurrency/structured-cancellation"
  rules:
  '((conc-cancel-quiescent CONC-CANCEL-QUIES quint)
    (conc-cancel-orphan CONC-CANCEL-ORPHAN quint))
  dependencies:
  '((CONC-CANCEL-QUIES source)
    (CONC-CANCEL-QUIES profile)
    (CONC-CANCEL-QUIES method)
    (CONC-CANCEL-ORPHAN source)
    (CONC-CANCEL-ORPHAN profile)
    (CONC-CANCEL-ORPHAN method))
  invariant: "Parent scope exits only after every spawned child task completes draining, preventing orphaned effects after scope close."
  limits: "Finite 2-child structured concurrency abstraction; does not model OS thread scheduling, panic unwinding, or non-cooperative blocking I/O.")
