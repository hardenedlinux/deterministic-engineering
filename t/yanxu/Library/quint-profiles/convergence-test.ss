;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Loader-owned qualification tests for library/quint-profiles:
;;; verifies Yuanxu Design 165 7-Band Plural Profile Convergence across all 10
;;; co-located Quint subdomains (33 models) in init.ss:
;;;  - profile-catalog: auto-discovery off QuintProfiles (zero manual registry wiring)
;;;  - by-tag global profiles (assurance.bounded-proof, bound.standard, governance.mandatory-countermodels)
;;;  - per-module bound overrides (extended-counterexample, deep-counterexample, compact)
;;;  - stateless pure reference models (capabilities, authority-currentness) exempt from countermodel floor
;;;  - Band 5 monotonic GovernanceFloor refuses weakening require-countermodels? to #f
;;;  - zero-recompilation runtime overlay switches stage:'runtime slot and rejects stage:'assembly mutation
(import :std/test
        :std/source
        :clan/poo/object
        (only-in :tao3k/yuanxu/module-system/interface yuanxu-load-modules)
        (only-in :tao3k/yuanxu/module-system/convergence/types make-global-profile by-tag)
        :deterministic-engineering/library/quint-profiles/objects)
(export quint-profiles-convergence-test)

(def repo-root
  (path-normalize (path-expand "../../../.." (path-directory (this-source-file)))))
(def init-path (path-expand "init.ss" repo-root))

(def wal-id
  'deterministic-engineering/packages/quint-models/engineering/storage/wal-crash-recovery/interface)
(def mvcc-id
  'deterministic-engineering/packages/quint-models/engineering/storage/mvcc-ssi-write-skew/interface)
(def raft-id
  'deterministic-engineering/packages/quint-models/engineering/consensus/raft-leader-commitment/interface)
(def hp-id
  'deterministic-engineering/packages/quint-models/engineering/parallel/hazard-pointers-tso/interface)
(def tls-id
  'deterministic-engineering/packages/quint-models/threat/protocol/tls13-0rtt-forward-secrecy/interface)
(def cap-id
  'deterministic-engineering/packages/quint-models/threat/execution/capabilities/interface)
(def auth-id
  'deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/interface)

(def quint-profiles-convergence-test
  (test-suite "Quint 3-axis Profile Namespace (assurance.*, bound.*, governance.*) over 10 subdomains"
    (test-case "all 33 co-located models converge cleanly via profile-catalog auto-discovery and by-tag targeting"
      (def view (yuanxu-load-modules init-path))
      (def graph (.ref view 'selected-graph))
      (def res (converge-quint-graph graph))
      (check-equal? (.ref res 'status) 'ready)
      (check-equal? (.ref res 'diagnostics) '())
      (def eff (.ref res 'effective-configs))
      ;; Standard stateful model inherits bound.standard (12 / 6) + Band 5 floor (#t).
      (check-equal? (.ref (.ref eff wal-id) 'verify-depth) 12)
      (check-equal? (.ref (.ref eff wal-id) 'countermodel-depth) 6)
      (check-equal? (.ref (.ref eff wal-id) 'require-countermodels?) #t)
      (check-equal? (.ref (.ref eff wal-id) 'verification-mode) 'bounded-proof)
      ;; Extended-counterexample overrides (10 / 9): MVCC/SSI and Raft.
      (check-equal? (.ref (.ref eff mvcc-id) 'verify-depth) 10)
      (check-equal? (.ref (.ref eff mvcc-id) 'countermodel-depth) 9)
      (check-equal? (.ref (.ref eff raft-id) 'verify-depth) 10)
      (check-equal? (.ref (.ref eff raft-id) 'countermodel-depth) 9)
      ;; Deep-counterexample override (12 / 9): Hazard Pointers TSO.
      (check-equal? (.ref (.ref eff hp-id) 'verify-depth) 12)
      (check-equal? (.ref (.ref eff hp-id) 'countermodel-depth) 9)
      ;; Compact override (10 / 6): TLS 1.3 0-RTT.
      (check-equal? (.ref (.ref eff tls-id) 'verify-depth) 10)
      (check-equal? (.ref (.ref eff tls-id) 'countermodel-depth) 6)
      ;; Stateless pure reference models keep require-countermodels?: #f (exempt from stateful floor).
      (check-equal? (.ref (.ref eff cap-id) 'require-countermodels?) #f)
      (check-equal? (.ref (.ref eff auth-id) 'require-countermodels?) #f))

    (test-case "Band 5 monotonic governance-floor cannot be weakened and runtime overlay switches mode cold"
      (def view (yuanxu-load-modules init-path))
      (def graph (.ref view 'selected-graph))
      ;; Hostile profile attempts to weaken require-countermodels? to #f across all quint.model units;
      ;; Band 5 governance-floor monotonic meet preserves #t on stateful models.
      (def hostile-reg
        (object<-alist
          (list
            (cons 'bound.standard
                  (make-global-profile 'bound.standard
                    (list (by-tag 'quint.model))
                    (.o verify-depth: 12
                        countermodel-depth: 6
                        require-countermodels?: #f))))))
      (def res (converge-quint-graph graph hostile-reg))
      (check-equal? (.ref res 'status) 'ready)
      (check-equal? (.ref (.ref (.ref res 'effective-configs) wal-id) 'require-countermodels?) #t)
      (check-equal? (.ref (.ref (.ref res 'effective-configs) tls-id) 'require-countermodels?) #t)
      (check-equal? (.ref (.ref (.ref res 'effective-configs) cap-id) 'require-countermodels?) #f)
      ;; Zero-recompilation runtime overlay switches stage:'runtime verification-mode.
      (def rt-res
        (apply-quint-runtime-profile graph res
          (list (cons wal-id (.o verification-mode: 'mbt-oracle)))))
      (check-equal? (.ref rt-res 'status) 'ready)
      (check-equal? (.ref (.ref (.ref rt-res 'effective-configs) wal-id) 'verification-mode) 'mbt-oracle)
      (check-equal? (.ref (.ref (.ref rt-res 'effective-configs) mvcc-id) 'verification-mode) 'bounded-proof)
      ;; Runtime mutation of stage:'assembly slot (verify-depth) is strictly rejected.
      (def bad-rt
        (apply-quint-runtime-profile graph res
          (list (cons wal-id (.o verify-depth: 2)))))
      (check-equal? (.ref bad-rt 'status) 'rejected))))
