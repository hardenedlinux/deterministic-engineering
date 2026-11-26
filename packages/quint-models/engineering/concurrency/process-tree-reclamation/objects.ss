;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; 3-tier process tree reclamation, graceful shutdown escalation, and kernel
;;; fate-sharing containment model (grounded in asp_http_e2e GatewayGuard::drop
;;; SIGKILL orphan leak, 10.154). Co-located Yuanxu unit alongside
;;; ProcessTreeReclamation.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export ProcessTreeReclamationModel
        PrematureSigkillCountermodel
        HttpAckNotQuiescenceCountermodel
        SinglePidKillNoContainmentCountermodel
        PgidSpawnToctouCountermodel
        PidReuseDoubleKillCountermodel)

(.def (ProcessTreeReclamationModel @ ThreatModel.)
  identity: 'engineering.concurrency.process-tree-reclamation
  family: 'engineering.concurrency.process-tree-reclamation
  title: "3-Tier Process Tree Reclamation, Graceful Escalation & Kernel Fate-Sharing"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("Linux cgroup v2 Documentation (cgroup.kill / cgroup.freeze)"
     "Atomic subtree termination eliminating fork/setsid TOCTOU races on process trees.")
    ("POSIX.1-2017 & Linux pidfd(2) / PR_SET_CHILD_SUBREAPER"
     "Race-free PID signaling and subreaper orphan reclamation across multi-tier supervision trees.")
    ("DE Architecture 10.154"
     "Multi-Method Fun-Flow Runnable Interface, LeanPoo Package Family, and Anti-Leak Verification Architecture."))
  quint-module: "concurrency_process_tree_reclamation"
  quint-file: "ProcessTreeReclamation.qnt"
  domain-dir: "engineering/concurrency/process-tree-reclamation"
  quint-imports: '()
  rules:
  '((conc-ptree-no-orphan CONC-PTREE-NO-ORPHAN quint)
    (conc-ptree-escalation CONC-PTREE-ESCALATION quint)
    (conc-ptree-containment CONC-PTREE-CONTAINMENT quint))
  dependencies:
  '((CONC-PTREE-NO-ORPHAN source)
    (CONC-PTREE-NO-ORPHAN profile)
    (CONC-PTREE-NO-ORPHAN method)
    (CONC-PTREE-ESCALATION source)
    (CONC-PTREE-ESCALATION profile)
    (CONC-PTREE-ESCALATION method)
    (CONC-PTREE-CONTAINMENT source)
    (CONC-PTREE-CONTAINMENT profile)
    (CONC-PTREE-CONTAINMENT method))
  invariant: "Guardian reaps only after all descendants exit; hard SIGKILL never preempts cooperative drain before grace expiry or observed hang; container kill eliminates entire subtree without spawn-escape or post-reap PID reuse signals."
  parameters: '()
  ;; guardian:   0=Running, 1=GracefulSent, 2=EscalatedKill, 3=Reaped
  ;; supervisor: 0=Alive, 1=HttpAcked, 2=Draining, 3=ExitedClean, 4=KilledHard, 5=Hung
  ;; c1, c2:     0=Idle, 1=Running, 2=Draining, 3=Exited, 4=Orphaned
  state:
  '((guardian "int" "0")
    (supervisor "int" "0")
    (c1 "int" "0")
    (c2 "int" "0")
    (graceExpired "bool" "false")
    (containerFrozen "bool" "false")
    (containerKilled "bool" "false")
    (prematureKill "bool" "false")
    (postReapSignal "bool" "false")
    (spawnEscaped "bool" "false"))
  guards:
  '((grace-or-exit-barrier
      (or (. h graceExpired) (= (. h supervisor) 5)))
    (waitpid-reaped-before-kill
      (and (= (. h supervisor) 3)
           (or (= (. h c1) 0) (= (. h c1) 3))
           (or (= (. h c2) 0) (= (. h c2) 3))))
    (kernel-tree-containment #t)
    (atomic-freeze-or-container
      (and (not (. h containerFrozen)) (not (. h containerKilled))))
    (not-yet-reaped
      (< (. h guardian) 3)))
  transitions:
  '((descendantsQuiescent
      (val descendantsQuiescent
        (and (or (= (. h c1) 0) (= (. h c1) 3))
             (or (= (. h c2) 0) (= (. h c2) 3)))))
    (spawnC1
      (action spawnC1 ()
        (if (and (= (. h supervisor) 0)
                 (= (. h c1) 0)
                 (not (. h containerFrozen))
                 (not (. h containerKilled)))
          (set-h (c1 1))
          (keep-h))))
    (spawnC2
      (action spawnC2 ()
        (if (and (= (. h c2) 0)
                 (< (. h supervisor) 3)
                 (guard atomic-freeze-or-container
                        (and (not (. h containerFrozen)) (not (. h containerKilled)))))
          (set-h (c2 1)
                 (spawnEscaped (or (. h spawnEscaped) (. h containerFrozen) (. h containerKilled))))
          (keep-h))))
    (sendShutdown
      (action sendShutdown ()
        (if (= (. h guardian) 0)
          (set-h (guardian 1))
          (keep-h))))
    (supervisorHttpAck
      (action supervisorHttpAck ()
        (if (and (= (. h guardian) 1) (= (. h supervisor) 0))
          (set-h (supervisor 1))
          (keep-h))))
    (supervisorBeginDrain
      (action supervisorBeginDrain ()
        (if (and (= (. h guardian) 1) (or (= (. h supervisor) 0) (= (. h supervisor) 1)))
          (set-h (supervisor 2)
                 (c1 (if (= (. h c1) 1) 2 (. h c1)))
                 (c2 (if (= (. h c2) 1) 2 (. h c2))))
          (keep-h))))
    (childC1Exit
      (action childC1Exit ()
        (if (or (= (. h c1) 1) (= (. h c1) 2))
          (set-h (c1 3))
          (keep-h))))
    (childC2Exit
      (action childC2Exit ()
        (if (or (= (. h c2) 1) (= (. h c2) 2))
          (set-h (c2 3))
          (keep-h))))
    (supervisorCleanExit
      (action supervisorCleanExit ()
        (if (and (= (. h supervisor) 2) descendantsQuiescent)
          (set-h (supervisor 3))
          (keep-h))))
    (supervisorHang
      (action supervisorHang ()
        (if (and (= (. h guardian) 1) (< (. h supervisor) 3))
          (set-h (supervisor 5))
          (keep-h))))
    (expireGraceTimer
      (action expireGraceTimer ()
        (if (and (= (. h guardian) 1) (not (. h graceExpired)))
          (set-h (graceExpired #t))
          (keep-h))))
    (freezeContainer
      (action freezeContainer ()
        (if (and (= (. h guardian) 1)
                 (or (. h graceExpired) (= (. h supervisor) 5))
                 (not (. h containerFrozen)))
          (set-h (containerFrozen #t))
          (keep-h))))
    (escalateKill
      (action escalateKill ()
        (if (and (= (. h guardian) 1)
                 (guard grace-or-exit-barrier (or (. h graceExpired) (= (. h supervisor) 5))))
          (set-h (guardian 2)
                 (supervisor 4)
                 (containerFrozen #t)
                 (containerKilled (guard kernel-tree-containment #t #f))
                 (c1 (if (guard kernel-tree-containment #t #f)
                       (if (or (= (. h c1) 1) (= (. h c1) 2)) 3 (. h c1))
                       (if (or (= (. h c1) 1) (= (. h c1) 2)) 4 (. h c1))))
                 (c2 (if (guard kernel-tree-containment #t #f)
                       (if (or (= (. h c2) 1) (= (. h c2) 2)) 3 (. h c2))
                       (if (or (= (. h c2) 1) (= (. h c2) 2)) 4 (. h c2))))
                 (prematureKill (or (. h prematureKill)
                                    (and (not (. h graceExpired)) (!= (. h supervisor) 5)))))
          (keep-h))))
    (reapAfterShutdown
      (action reapAfterShutdown ()
        (if (and (= (. h guardian) 1)
                 (guard waitpid-reaped-before-kill (and (= (. h supervisor) 3) descendantsQuiescent)))
          (set-h (guardian 3))
          (keep-h))))
    (reapAfterKill
      (action reapAfterKill ()
        (if (and (= (. h guardian) 2) (. h containerKilled) descendantsQuiescent)
          (set-h (guardian 3))
          (keep-h))))
    (signalSupervisor
      (action signalSupervisor ()
        (if (and (or (= (. h guardian) 1) (= (. h guardian) 3))
                 (guard not-yet-reaped (< (. h guardian) 3)))
          (set-h (postReapSignal (or (. h postReapSignal) (= (. h guardian) 3))))
          (keep-h))))
    (step
      (action step ()
        (any spawnC1 spawnC2 sendShutdown supervisorHttpAck supervisorBeginDrain
             childC1Exit childC2Exit supervisorCleanExit supervisorHang
             expireGraceTimer freezeContainer escalateKill
             reapAfterShutdown reapAfterKill signalSupervisor))))
  safety:
  '(and (not (. h prematureKill))
        (not (. h postReapSignal))
        (not (. h spawnEscaped))
        (!= (. h c1) 4)
        (!= (. h c2) 4)
        (or (!= (. h guardian) 3) descendantsQuiescent))
  traces:
  '((gracefulCleanExitTest
      (run gracefulCleanExitTest
        (then init spawnC1 sendShutdown supervisorHttpAck supervisorBeginDrain
              childC1Exit supervisorCleanExit reapAfterShutdown
              (all (assert (= (. h guardian) 3))
                   (assert (= (. h c1) 3))
                   (assert safety)
                   (keep-h)))))
    (hungSupervisorEscalationTest
      (run hungSupervisorEscalationTest
        (then init spawnC1 sendShutdown supervisorHang expireGraceTimer
              freezeContainer escalateKill reapAfterKill
              (all (assert (= (. h guardian) 3))
                   (assert (. h containerKilled))
                   (assert (= (. h c1) 3))
                   (assert safety)
                   (keep-h)))))
    (prematureSigkillCounterTest
      (run prematureSigkillCounterTest
        (then init spawnC1 sendShutdown escalateKillPremature
              (all (assert (. h prematureKill))
                   (assert (not safety))
                   (keep-h)))))
    (singlePidOrphanCounterTest
      (run singlePidOrphanCounterTest
        (then init spawnC1 sendShutdown expireGraceTimer escalateKillSinglePid
              (all (assert (= (. h c1) 4))
                   (assert (not safety))
                   (keep-h))))))
  countermodels:
  (list PrematureSigkillCountermodel
        HttpAckNotQuiescenceCountermodel
        SinglePidKillNoContainmentCountermodel
        PgidSpawnToctouCountermodel
        PidReuseDoubleKillCountermodel)
  limits: "Finite 2-grandchild 3-tier process tree abstraction; OS kernel scheduling, cgroup v2 / Darwin kqueue implementation fidelity, and arbitrary-depth tree induction are discharged separately by LeanPoo Core.Containment and native SIGKILL Leak Oracles.")

(.def (PrematureSigkillCountermodel @ ProcessTreeReclamationModel)
  identity: 'engineering.concurrency.process-tree-reclamation.premature-sigkill
  dropped-guard: 'grace-or-exit-barrier
  step-action: "stepPrematureSigkill"
  derive-from-transition: 'escalateKill
  derive-action-name: 'escalateKillPremature
  expected-itf-predicate: "h.prematureKill == true")

(.def (HttpAckNotQuiescenceCountermodel @ ProcessTreeReclamationModel)
  identity: 'engineering.concurrency.process-tree-reclamation.http-ack-not-quiescence
  dropped-guard: 'waitpid-reaped-before-kill
  step-action: "stepHttpAckNotQuiescence"
  derive-from-transition: 'reapAfterShutdown
  derive-action-name: 'reapAfterHttpAckUnchecked
  expected-itf-predicate: "h.guardian == 3 and (h.c1 == 1 or h.c2 == 1)")

(.def (SinglePidKillNoContainmentCountermodel @ ProcessTreeReclamationModel)
  identity: 'engineering.concurrency.process-tree-reclamation.single-pid-kill-no-containment
  dropped-guard: 'kernel-tree-containment
  step-action: "stepSinglePidKillNoContainment"
  derive-from-transition: 'escalateKill
  derive-action-name: 'escalateKillSinglePid
  expected-itf-predicate: "h.c1 == 4 or h.c2 == 4")

(.def (PgidSpawnToctouCountermodel @ ProcessTreeReclamationModel)
  identity: 'engineering.concurrency.process-tree-reclamation.pgid-spawn-toctou
  dropped-guard: 'atomic-freeze-or-container
  step-action: "stepPgidSpawnToctou"
  derive-from-transition: 'spawnC2
  derive-action-name: 'spawnC2Unfrozen
  expected-itf-predicate: "h.spawnEscaped == true")

(.def (PidReuseDoubleKillCountermodel @ ProcessTreeReclamationModel)
  identity: 'engineering.concurrency.process-tree-reclamation.pid-reuse-double-kill
  dropped-guard: 'not-yet-reaped
  step-action: "stepPidReuseDoubleKill"
  derive-from-transition: 'signalSupervisor
  derive-action-name: 'signalSupervisorPostReap
  expected-itf-predicate: "h.postReapSignal == true")
