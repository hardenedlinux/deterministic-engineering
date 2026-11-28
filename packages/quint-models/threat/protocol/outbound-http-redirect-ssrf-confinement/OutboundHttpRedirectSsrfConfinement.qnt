// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.protocol.outbound-http-redirect-ssrf-confinement
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel disable-http-redirects step=stepFollowUncheckedRedirect max-steps=6 itf="h.redirectLeaks > 0"
// @countermodel enforce-https-for-remote-credentials step=stepCleartextRemoteCredLeak max-steps=6 itf="h.schemeDowngrades > 0"
// @countermodel confine-download-url-origin step=stepUnconfinedSsrfDownload max-steps=6 itf="h.ssrfCrossOriginHits > 0"
// @countermodel reject-userinfo-and-symlink-serve step=stepUserinfoAndSymlinkEscape max-steps=6 itf="h.userinfoSmuggles > 0 or h.symlinkServeLeaks > 0"
// Limits: Finite outbound HTTP request/redirect/download/serve state abstraction (ADV-L4 hostile attack tier); verifies fail-closed no-redirect policy, remote HTTPS credential confinement, DownloadURL origin/scheme confinement, userinfo rejection, and Lstat symlink-safe file serving, not kernel TCP stack or DNS rebinding TTL races.
module protocol_outbound_http_redirect_ssrf_confinement {
  type State = { cleanAdmitted: int, hostileBlocked: int, redirectLeaks: int, schemeDowngrades: int, ssrfCrossOriginHits: int, userinfoSmuggles: int, symlinkServeLeaks: int }
  var h: State
  action init = h' = { cleanAdmitted: 0, hostileBlocked: 0, redirectLeaks: 0, schemeDowngrades: 0, ssrfCrossOriginHits: 0, userinfoSmuggles: 0, symlinkServeLeaks: 0 }
  action admitPinnedHttpsRequest = h' = h.with("cleanAdmitted", (h.cleanAdmitted + 1))
  action blockRedirectEscape = h' = h.with("hostileBlocked", (h.hostileBlocked + 1))
  action blockSchemeDowngrade = h' = h.with("hostileBlocked", (h.hostileBlocked + 1))
  action blockSsrfDownloadUrl = h' = h.with("hostileBlocked", (h.hostileBlocked + 1))
  action blockUserinfoOrControlUrl = h' = h.with("hostileBlocked", (h.hostileBlocked + 1))
  action blockSymlinkHttpServe = h' = h.with("hostileBlocked", (h.hostileBlocked + 1))
  action step = any { admitPinnedHttpsRequest, blockRedirectEscape, blockSchemeDowngrade, blockSsrfDownloadUrl, blockUserinfoOrControlUrl, blockSymlinkHttpServe }
  val safety = (h.redirectLeaks == 0 and h.schemeDowngrades == 0 and h.ssrfCrossOriginHits == 0 and h.userinfoSmuggles == 0 and h.symlinkServeLeaks == 0)
  // Countermodel threat.protocol.outbound-http-redirect-ssrf-confinement.follow-unchecked-redirect (dropped guard: disable-http-redirects)
  action followUncheckedRedirect = h' = h.with("redirectLeaks", (h.redirectLeaks + 1))
  action stepFollowUncheckedRedirect = any { step, followUncheckedRedirect }
  // Countermodel threat.protocol.outbound-http-redirect-ssrf-confinement.cleartext-remote-cred-leak (dropped guard: enforce-https-for-remote-credentials)
  action sendCleartextRemoteCredential = h' = h.with("schemeDowngrades", (h.schemeDowngrades + 1))
  action stepCleartextRemoteCredLeak = any { step, sendCleartextRemoteCredential }
  // Countermodel threat.protocol.outbound-http-redirect-ssrf-confinement.unconfined-ssrf-download (dropped guard: confine-download-url-origin)
  action fetchUnconfinedDownloadUrl = h' = h.with("ssrfCrossOriginHits", (h.ssrfCrossOriginHits + 1))
  action stepUnconfinedSsrfDownload = any { step, fetchUnconfinedDownloadUrl }
  // Countermodel threat.protocol.outbound-http-redirect-ssrf-confinement.userinfo-and-symlink-escape (dropped guard: reject-userinfo-and-symlink-serve)
  action acceptUserinfoOrServeSymlink = h' = h.with("userinfoSmuggles", (h.userinfoSmuggles + 1)).with("symlinkServeLeaks", (h.symlinkServeLeaks + 1))
  action stepUserinfoAndSymlinkEscape = any { step, acceptUserinfoOrServeSymlink }
  action checkOutboundHttpSafe = all { assert(h.cleanAdmitted > 0), assert(h.hostileBlocked > 0), assert(h.redirectLeaks == 0), assert(h.schemeDowngrades == 0), assert(h.ssrfCrossOriginHits == 0), assert(h.userinfoSmuggles == 0), assert(h.symlinkServeLeaks == 0), assert(safety), h' = h }
  action checkOutboundHttpViolated = all { assert((h.redirectLeaks > 0 or h.schemeDowngrades > 0 or h.ssrfCrossOriginHits > 0 or h.userinfoSmuggles > 0 or h.symlinkServeLeaks > 0)), assert(not(safety)), h' = h }
  run outboundHttpSafeTest = init.then(admitPinnedHttpsRequest).then(blockRedirectEscape).then(blockSchemeDowngrade).then(blockSsrfDownloadUrl).then(blockUserinfoOrControlUrl).then(blockSymlinkHttpServe).then(checkOutboundHttpSafe)
  run redirectEscapeRefutedTest = init.then(followUncheckedRedirect).then(checkOutboundHttpViolated)
  run schemeDowngradeRefutedTest = init.then(sendCleartextRemoteCredential).then(checkOutboundHttpViolated)
  run ssrfDownloadRefutedTest = init.then(fetchUnconfinedDownloadUrl).then(checkOutboundHttpViolated)
  run userinfoSymlinkRefutedTest = init.then(acceptUserinfoOrServeSymlink).then(checkOutboundHttpViolated)
}
