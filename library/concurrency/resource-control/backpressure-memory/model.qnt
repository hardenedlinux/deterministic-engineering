// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

// Project-owned bounded abstraction; no Rust scheduler or allocation claim.
module BackpressureOwners {
  type State = {
    limit: int, queueLimit: int, admitted: Set[int], queued: Set[int], running: Set[int],
    returned: Set[int], cleanup: Set[int], done: Set[int]
  }
  var s: State
  pure val jobs = Set(0, 1, 2, 3, 4)
  pure def initial: State = {
    limit: 2, queueLimit: 2, admitted: Set(), queued: Set(), running: Set(),
    returned: Set(), cleanup: Set(), done: Set()
  }
  action init = s' = initial
  action initResource = s' = { ...initial, limit: 1, queueLimit: 1 }
  action initResourceRunning = s' = { ...initial, limit: 1, queueLimit: 1, admitted: Set(0), running: Set(0) }
  action initC2 = s' = { ...initial, limit: 4 }
  action initRunning = s' = { ...initial, admitted: Set(0), running: Set(0) }
  val owners = s.queued.union(s.running).union(s.returned).union(s.cleanup)
  val safe = all {
    owners == s.admitted,
    s.admitted.size() <= s.limit,
    s.queued.size() <= s.queueLimit,
    s.queued.intersect(s.running).size() == 0,
    s.queued.intersect(s.returned).size() == 0,
    s.queued.intersect(s.cleanup).size() == 0,
    s.running.intersect(s.returned).size() == 0,
    s.running.intersect(s.cleanup).size() == 0,
    s.returned.intersect(s.cleanup).size() == 0,
    s.done.intersect(owners).size() == 0
  }
  val hasCleanup = s.cleanup.size() > 0
  val hasReturned = s.returned.size() > 0
  val allDone = s.done == jobs
  action admit = {
    nondet j = jobs.oneOf()
    all { not(owners.contains(j)), not(s.done.contains(j)),
      s.admitted.size() < s.limit, s.queued.size() < s.queueLimit,
      s' = { ...s, admitted: s.admitted.union(Set(j)), queued: s.queued.union(Set(j)) } }
  }
  action start = {
    nondet j = jobs.oneOf()
    all { s.queued.contains(j), s' = { ...s,
      queued: s.queued.exclude(Set(j)), running: s.running.union(Set(j)) } }
  }
  action finish = {
    nondet j = jobs.oneOf()
    all { s.running.contains(j), s' = { ...s,
      running: s.running.exclude(Set(j)), returned: s.returned.union(Set(j)) } }
  }
  action cancel = {
    nondet j = jobs.oneOf()
    all { s.running.contains(j), s' = { ...s,
      running: s.running.exclude(Set(j)), cleanup: s.cleanup.union(Set(j)) } }
  }
  action drain = {
    nondet j = jobs.oneOf()
    all { s.returned.contains(j), s' = { ...s,
      returned: s.returned.exclude(Set(j)), admitted: s.admitted.exclude(Set(j)),
      done: s.done.union(Set(j)) } }
  }
  action clean = {
    nondet j = jobs.oneOf()
    all { s.cleanup.contains(j), s' = { ...s,
      cleanup: s.cleanup.exclude(Set(j)), admitted: s.admitted.exclude(Set(j)),
      done: s.done.union(Set(j)) } }
  }
  action step = any { admit, start, finish, cancel, drain, clean, s' = s }
  // Independent negative schedule: cancellation abandons its permit, yet the
  // non-abortable CPU job still owns its payload in cleanup.
  action earlyRelease = s' = { ...s,
    running: Set(), cleanup: Set(0), admitted: Set() }
}
