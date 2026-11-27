;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; E3.2: Scheme half of the 16-case AI Agent Defensive Coding Benchmark (30.05).
;;; Tests real S-expression AST extraction (audit-scheme-defensive-datums) across:
;;;   - 4 negative cases (AG03, AG06, AG09, AG12) covering all 4 G2 hallucination classes
;;;   - 2 real-file positive controls (AG15 defensive-boundaries/objects.ss, AG16 quint-profiles/objects.ss)
(import :std/test
        (only-in "../../../support/repo-paths.ss" resolve-repo-root)
        (only-in :tao3k/yuanxu/testing yuanxu-test-case)
        :std/source
        :clan/poo/object
        :deterministic-engineering/library/defensive-governance/func)
(export agent-defensive-scheme-benchmark-test)

(def repo-root
  (resolve-repo-root))

(def (read-scheme-file-datums rel-path)
  (call-with-input-file (path-expand rel-path repo-root)
    (lambda (port)
      (let loop ((acc '()))
        (let (form (read port))
          (if (eof-object? form) (reverse acc) (loop (cons form acc))))))))

(def agent-defensive-scheme-benchmark-test
  (test-suite "E3.2 Agent Defensive Coding Benchmark (Scheme AST, 30.05)"
    (yuanxu-test-case "catches all 4 Scheme G2 hallucination classes (AG03, AG06, AG09, AG12) with 100% recall"
      ;; AG03: silent-fallback via with-catch returning constant empty list
      (def r03 (audit-scheme-defensive-datums
                 '((def (bad-parse x) (with-catch (lambda (_) '()) (lambda () (parse x)))))))
      (check-equal? (.get r03 passed?) #f)
      (check-equal? (and (memq 'silent-fallback (map car (.get r03 findings))) #t) #t)

      ;; AG06: floor-weakening via allow-global-purge?: #t and require-use-time-witness?: #f
      (def r06 (audit-scheme-defensive-datums
                 '((def hostile (.o allow-global-purge?: #t require-use-time-witness?: #f)))))
      (check-equal? (.get r06 passed?) #f)
      (check-equal? (and (memq 'floor-weakening (map car (.get r06 findings))) #t) #t)

      ;; AG09: redundant-defensive-glue via vacuous (guard always-true #t)
      (def r09 (audit-scheme-defensive-datums
                 '((action step () (all (guard vacuous-check #t) (keep-h))))))
      (check-equal? (.get r09 passed?) #f)
      (check-equal? (and (memq 'redundant-defensive-glue (map car (.get r09 findings))) #t) #t)

      ;; AG12: fabricated-evidence via verified?: #t paired with witness: #f
      (def r12 (audit-scheme-defensive-datums
                 '((def fake-receipt (.o verified?: #t witness: #f)))))
      (check-equal? (.get r12 passed?) #f)
      (check-equal? (and (memq 'fabricated-evidence (map car (.get r12 findings))) #t) #t))

    (yuanxu-test-case "zero false positives on real maintained library Scheme files (AG15, AG16)"
      ;; AG15: real library/defensive-boundaries/objects.ss
      (def r15 (audit-scheme-defensive-datums
                 (read-scheme-file-datums "library/defensive-boundaries/objects.ss")))
      (check-equal? (.get r15 passed?) #t)
      (check-equal? (.get r15 findings) '())

      ;; AG16: real library/defensive-governance/objects.ss
      (def r16 (audit-scheme-defensive-datums
                 (read-scheme-file-datums "library/defensive-governance/objects.ss")))
      (check-equal? (.get r16 passed?) #t)
      (check-equal? (.get r16 findings) '()))))
