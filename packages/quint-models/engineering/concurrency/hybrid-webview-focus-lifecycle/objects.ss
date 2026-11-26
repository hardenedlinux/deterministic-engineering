;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Hybrid GPU + sandboxed WebView async lifecycle, focus handoff & tier isolation model.
;;; Co-located Yuanxu unit: single source of truth alongside HybridWebViewFocusLifecycle.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export HybridWebViewFocusLifecycleModel
        SyncMountStallCountermodel
        HiddenFocusLeakCountermodel
        UntrustedRpcEscalationCountermodel)

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
  quint-imports: '()
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
  parameters: '()
  ;; wvState: 0=Unmounted, 1=WarmingAsync, 2=Ready, 3=Crashed
  ;; tier: 0=Tier-0 First-Party Studio, 2=Tier-2 Untrusted User Island
  state:
  '((wvState "int" "0")
    (wvShown "bool" "false")
    (wvFocused "bool" "false")
    (renderBlocked "bool" "false")
    (tier "int" "2")
    (rpcInvokedByTier "int" "0"))
  guards:
  '((async-warmup-off-render
      (not (. h renderBlocked)))
    (revoke-focus-on-hide
      (or (. h wvShown) (not (. h wvFocused))))
    (tier0-rpc-capability-gate
      (= (. h tier) 0)))
  transitions:
  '((selectTier0
      (action selectTier0 ()
        (if (= (. h wvState) 0)
          (set-h (tier 0))
          (keep-h))))
    (requestMount
      (action requestMount ()
        (if (= (. h wvState) 0)
          (set-h (wvState 1)
                 (wvShown #t)
                 (renderBlocked (guard async-warmup-off-render #f #t)))
          (keep-h))))
    (finishWarmup
      (action finishWarmup ()
        (if (= (. h wvState) 1)
          (set-h (wvState 2))
          (keep-h))))
    (focusWebView
      (action focusWebView ()
        (if (and (= (. h wvState) 2) (. h wvShown))
          (set-h (wvFocused #t))
          (keep-h))))
    (hideTab
      (action hideTab ()
        (if (. h wvShown)
          (set-h (wvShown #f)
                 (wvFocused (guard revoke-focus-on-hide #f (. h wvFocused))))
          (keep-h))))
    (showTab
      (action showTab ()
        (if (and (not (. h wvShown)) (= (. h wvState) 2))
          (set-h (wvShown #t))
          (keep-h))))
    (crashWebContent
      (action crashWebContent ()
        (if (= (. h wvState) 2)
          (set-h (wvState 3)
                 (wvFocused #f))
          (keep-h))))
    (recoverWebContent
      (action recoverWebContent ()
        (if (= (. h wvState) 3)
          (set-h (wvState 1))
          (keep-h))))
    (invokeHostRpc
      (action invokeHostRpc ()
        (if (and (= (. h wvState) 2)
                 (guard tier0-rpc-capability-gate (= (. h tier) 0)))
          (set-h (rpcInvokedByTier (. h tier)))
          (keep-h))))
    (step
      (action step ()
        (any selectTier0 requestMount finishWarmup focusWebView hideTab
             showTab crashWebContent recoverWebContent invokeHostRpc))))
  safety:
  '(and (not (. h renderBlocked))
        (or (. h wvShown) (not (. h wvFocused)))
        (= (. h rpcInvokedByTier) 0))
  traces:
  '((safeLifecycleAndRecoveryTest
      (run safeLifecycleAndRecoveryTest
        (then init selectTier0 requestMount finishWarmup focusWebView invokeHostRpc hideTab crashWebContent recoverWebContent finishWarmup
              (all (assert (not (. h wvFocused)))
                   (assert (= (. h rpcInvokedByTier) 0))
                   (assert safety)
                   (keep-h)))))
    (syncMountStallViolatesSafetyTest
      (run syncMountStallViolatesSafetyTest
        (then init requestMountSync
              (all (assert (. h renderBlocked))
                   (assert (not safety))
                   (keep-h)))))
    (hiddenFocusLeakViolatesSafetyTest
      (run hiddenFocusLeakViolatesSafetyTest
        (then init requestMount finishWarmup focusWebView hideTabLeaky
              (all (assert (not (. h wvShown)))
                   (assert (. h wvFocused))
                   (assert (not safety))
                   (keep-h)))))
    (untrustedRpcViolatesSafetyTest
      (run untrustedRpcViolatesSafetyTest
        (then init requestMount finishWarmup invokeHostRpcUnchecked
              (all (assert (= (. h rpcInvokedByTier) 2))
                   (assert (not safety))
                   (keep-h))))))
  countermodels: (list SyncMountStallCountermodel HiddenFocusLeakCountermodel UntrustedRpcEscalationCountermodel)
  limits: "Finite single-island hybrid WebView lifecycle abstraction; does not model multi-window AppKit responder chains, OS-level OOM kills, or WebKit internal IPC queuing.")

(.def (SyncMountStallCountermodel @ HybridWebViewFocusLifecycleModel)
  identity: 'engineering.concurrency.hybrid-webview-focus-lifecycle.sync-mount-stall
  dropped-guard: 'async-warmup-off-render
  step-action: "stepSyncMountStall"
  derive-from-transition: 'requestMount
  derive-action-name: 'requestMountSync
  expected-itf-predicate: "h.renderBlocked == true")

(.def (HiddenFocusLeakCountermodel @ HybridWebViewFocusLifecycleModel)
  identity: 'engineering.concurrency.hybrid-webview-focus-lifecycle.hidden-focus-leak
  dropped-guard: 'revoke-focus-on-hide
  step-action: "stepHiddenFocusLeak"
  derive-from-transition: 'hideTab
  derive-action-name: 'hideTabLeaky
  expected-itf-predicate: "h.wvShown == false and h.wvFocused == true")

(.def (UntrustedRpcEscalationCountermodel @ HybridWebViewFocusLifecycleModel)
  identity: 'engineering.concurrency.hybrid-webview-focus-lifecycle.untrusted-rpc-escalation
  dropped-guard: 'tier0-rpc-capability-gate
  step-action: "stepUntrustedRpcEscalation"
  derive-from-transition: 'invokeHostRpc
  derive-action-name: 'invokeHostRpcUnchecked
  expected-itf-predicate: "h.rpcInvokedByTier == 2")
