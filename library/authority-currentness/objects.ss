;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Domain-owned authority currentness predicates; no Quint CLI or I/O here.
(import :clan/poo/object
        (only-in "../threat-capabilities/objects.ss" ThreatModel.))
(export AuthorityCurrentnessModel)

(.def (AuthorityCurrentnessModel @ ThreatModel.)
  identity: 'threat.authority-currentness
  family: 'threat.authority-currentness
  quint-module: "authority_currentness"
  quint-file: "AuthorityCurrentness.qnt"
  domain-dir: "threat/authority-currentness"
  rules: '((authority-currentness AUTH-CURR quint))
  dependencies: '((AUTH-CURR source) (AUTH-CURR profile) (AUTH-CURR method))
  invariant: "Authority is current only while unpaused, fresh, valid credential, intact bytes, and matching writer epoch."
  state: '((paused "bool")
           (fresh "bool")
           (credential "bool")
           (bytes "bool")
           (epoch "int")
           (planned "int"))
  guards: '((unpaused (not paused))
            (fresh fresh)
            (credential credential)
            (bytes bytes)
            (epoch-match (= epoch planned)))
  transitions:
  '((isCurrent
     (pure-def isCurrent ((paused "bool") (fresh "bool") (credential "bool") (bytes "bool")) "bool"
       (and (not paused) fresh credential bytes)))
    (epochCurrent
     (pure-def epochCurrent ((epoch "int") (planned "int")) "bool"
       (= epoch planned))))
  safety: #t
  traces:
  '((currentnessTest
     (run currentnessTest
       (all (assert (call isCurrent #f #t #t #t))
            (assert (not (call isCurrent #t #t #t #t)))
            (assert (not (call isCurrent #f #f #t #t)))
            (assert (not (call isCurrent #f #t #f #t)))
            (assert (not (call isCurrent #f #t #t #f)))
            (assert (call epochCurrent 0 0))
            (assert (not (call epochCurrent 1 0)))))))
  countermodels: '()
  parameters: '()
  limits: "Trusted boolean bits abstract real clock freshness, revocation checks, signature verification and writer fencing.")
