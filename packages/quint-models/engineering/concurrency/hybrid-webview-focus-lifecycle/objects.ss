;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Hybrid GPU + sandboxed WebView async lifecycle, focus handoff & tier isolation model.
;;; Co-located Yuanxu unit: single source of truth alongside HybridWebViewFocusLifecycle.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export HybridWebViewFocusLifecycleModel)

(.def (HybridWebViewFocusLifecycleModel @ ThreatModel.)
  identity: 'engineering.concurrency.hybrid-webview-focus-lifecycle
  family: 'engineering.concurrency.hybrid-webview-focus-lifecycle
  title: "Hybrid GPU & WebView Async Lifecycle, Focus Handoff & Trust Isolation"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("C. Reis, A. Moshchuk & N. Oskov (USENIX Security 2019)"
     "Site Isolation: Process Separation for Web Sites within the Browser — untrusted web content isolation.")
    ("N. J. Smith (2018)"
     "Notes on Structured Concurrency — async warmup and bounded recovery without main-thread stalls.")
    ("Tauri v2 Security Architecture (2024)"
     "Capability-scoped IPC boundaries separating trusted first-party surfaces from untrusted origins."))
  quint-module: "concurrency_hybrid_webview"
  quint-file: "HybridWebViewFocusLifecycle.qnt"
  domain-dir: "engineering/concurrency/hybrid-webview-focus-lifecycle"
  rules:
  '((webview-async-nonblocking WV-ASYNC-NONBLOCK quint)
    (webview-focus-handoff WV-FOCUS-HANDOFF quint)
    (webview-tier-isolation WV-TIER-ISO quint))
  dependencies:
  '((WV-ASYNC-NONBLOCK source)
    (WV-ASYNC-NONBLOCK profile)
    (WV-ASYNC-NONBLOCK method)
    (WV-FOCUS-HANDOFF source)
    (WV-FOCUS-HANDOFF profile)
    (WV-FOCUS-HANDOFF method)
    (WV-TIER-ISO source)
    (WV-TIER-ISO profile)
    (WV-TIER-ISO method))
  invariant: "WebView creation never blocks the GPU render thread, hiding a WebView tab always revokes its keyboard focus back to the native frame (not(wvShown) => not(wvFocused)), and Tier-2 untrusted islands never cross into Tier-0 host RPC."
  limits: "Finite single-island hybrid WebView lifecycle abstraction; does not model multi-window AppKit responder chains, OS-level OOM kills, or WebKit internal IPC queuing.")
