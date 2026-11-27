;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; 3-tier process tree reclamation, graceful shutdown escalation, and kernel
;;; fate-sharing containment model (grounded in asp_http_e2e GatewayGuard::drop
;;; SIGKILL orphan leak, 10.154). Co-located Yuanxu unit alongside
;;; ProcessTreeReclamation.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export ProcessTreeReclamationModel)

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
  limits: "Finite 2-grandchild 3-tier process tree abstraction; OS kernel scheduling, cgroup v2 / Darwin kqueue implementation fidelity, and arbitrary-depth tree induction are discharged separately by LeanPoo Core.Containment and native SIGKILL Leak Oracles.")
