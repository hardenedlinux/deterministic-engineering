;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Multi-Role Agent Chat Room Ingress, External Connector Provenance & Human-Only One-Shot Gate Governance.
;;; Co-located Yuanxu unit: single source of truth alongside ChatroomIngressGovernance.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export ChatroomIngressGovernanceModel)

(.def (ChatroomIngressGovernanceModel @ ThreatModel.)
  identity: 'threat.protocol.chatroom-ingress-governance
  family: 'threat.protocol.chatroom-ingress-governance
  title: "Multi-Role Chat Room External Ingress, Channel Isolation & Human-Only Gate Governance"
  subdomain: 'quint.threat.protocol
  papers:
  '(("E. Debenedetti et al. (2025)"
     "Defeating Prompt Injections by Design (CaMeL): untrusted external ingress taint containment and human-gated tool execution.")
    ("R. S. Sandhu, E. J. Coyne, H. L. Feinstein & C. E. Youman (IEEE Computer, 1996)"
     "Role-Based Access Control Models: separation of duty and non-delegable human approval authority in collaborative rooms."))
  quint-module: "chatroom_ingress_governance"
  quint-file: "ChatroomIngressGovernance.qnt"
  domain-dir: "threat/protocol/chatroom-ingress-governance"
  rules:
  '((ingress-origin-provenance ROOM-INGRESS-ORIGIN quint)
    (channel-thread-affinity ROOM-CHANNEL-AFFINITY quint)
    (gate-oneshot-pending ROOM-GATE-ONESHOT quint)
    (matter-gate-lock ROOM-MATTER-LOCK quint)
    (tainted-tool-human-gate ROOM-TAINT-GATE quint))
  dependencies:
  '((ROOM-INGRESS-ORIGIN source)
    (ROOM-INGRESS-ORIGIN profile)
    (ROOM-INGRESS-ORIGIN method)
    (ROOM-CHANNEL-AFFINITY source)
    (ROOM-CHANNEL-AFFINITY profile)
    (ROOM-CHANNEL-AFFINITY method)
    (ROOM-GATE-ONESHOT source)
    (ROOM-GATE-ONESHOT profile)
    (ROOM-GATE-ONESHOT method)
    (ROOM-MATTER-LOCK source)
    (ROOM-MATTER-LOCK profile)
    (ROOM-MATTER-LOCK method)
    (ROOM-TAINT-GATE source)
    (ROOM-TAINT-GATE profile)
    (ROOM-TAINT-GATE method))
  invariant: "External room ingress never forges origin or gate receipts and never injects across channels; approval gates resolve strictly once by a human operator; gate-blocked matters cannot be unblocked by AI agents; and untrusted external messages never trigger privileged tools without human gate approval."
  limits: "Finite multi-role agent chatroom ingress, channel affinity, and one-shot human gate governance abstraction; does not model cryptographic webhook HMAC algorithms, semantic LLM prompt classification, or federated transport encryption.")
