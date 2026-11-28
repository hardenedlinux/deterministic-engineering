// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.backpressure-memory
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel cancel-retains-permit step=stepEarlyRelease max-steps=6 itf="size(h.cleanup) > 0 and not(subseteq(h.cleanup, h.admitted))"
// @countermodel admit-capacity-bound step=stepOverAdmit max-steps=6 itf="size(h.admitted) > h.limit"
// @countermodel admit-queue-bound step=stepQueueOverflow max-steps=6 itf="size(h.queued) > h.queueLimit"
// @countermodel admit-disjoint-job step=stepDuplicateAdmit max-steps=6 itf="size(h.queued) + size(h.running) + size(h.returned) + size(h.cleanup) > size(h.admitted) or (size(h.done) > 0 and size(h.queued) > 0)"
// Limits: Finite-state bounded ownership abstraction over 4 discrete job IDs (limit=2, queueLimit=1); makes no Rust scheduler, allocator, byte-accounting, or kernel memory-reclamation claim.
module BackpressureOwners {
  type State = { limit: int, queueLimit: int, admitted: Set[int], queued: Set[int], running: Set[int], returned: Set[int], cleanup: Set[int], done: Set[int] }
  var h: State
  action init = h' = { limit: 2, queueLimit: 1, admitted: Set(), queued: Set(), running: Set(), returned: Set(), cleanup: Set(), done: Set() }
  pure val jobs = Set(0, 1, 2, 3)
  val owners = h.queued.union(h.running).union(h.returned).union(h.cleanup)
  action admitJob(j: int): bool = all { (not(owners.contains(j)) and not(h.done.contains(j))), size(h.admitted) < h.limit, size(h.queued) < h.queueLimit, h' = h.with("admitted", h.admitted.union(Set(j))).with("queued", h.queued.union(Set(j))) }
  action startJob(j: int): bool = all { h.queued.contains(j), h' = h.with("queued", h.queued.exclude(Set(j))).with("running", h.running.union(Set(j))) }
  action finishJob(j: int): bool = all { h.running.contains(j), h' = h.with("running", h.running.exclude(Set(j))).with("returned", h.returned.union(Set(j))) }
  action cancelJob(j: int): bool = all { h.running.contains(j), h' = h.with("running", h.running.exclude(Set(j))).with("cleanup", h.cleanup.union(Set(j))).with("admitted", h.admitted) }
  action drainJob(j: int): bool = all { h.returned.contains(j), h' = h.with("returned", h.returned.exclude(Set(j))).with("admitted", h.admitted.exclude(Set(j))).with("done", h.done.union(Set(j))) }
  action cleanJob(j: int): bool = all { h.cleanup.contains(j), h' = h.with("cleanup", h.cleanup.exclude(Set(j))).with("admitted", h.admitted.exclude(Set(j))).with("done", h.done.union(Set(j))) }
  action admit = { nondet j = jobs.oneOf()
    admitJob(j) }
  action start = { nondet j = jobs.oneOf()
    startJob(j) }
  action finish = { nondet j = jobs.oneOf()
    finishJob(j) }
  action cancel = { nondet j = jobs.oneOf()
    cancelJob(j) }
  action drain = { nondet j = jobs.oneOf()
    drainJob(j) }
  action clean = { nondet j = jobs.oneOf()
    cleanJob(j) }
  action step = any { admit, start, finish, cancel, drain, clean, h' = h }
  val safety = (owners == h.admitted and size(h.admitted) <= h.limit and size(h.queued) <= h.queueLimit and size(h.queued.intersect(h.running)) == 0 and size(h.queued.intersect(h.returned)) == 0 and size(h.queued.intersect(h.cleanup)) == 0 and size(h.running.intersect(h.returned)) == 0 and size(h.running.intersect(h.cleanup)) == 0 and size(h.returned.intersect(h.cleanup)) == 0 and size(h.done.intersect(owners)) == 0)
  // Countermodel engineering.concurrency.backpressure-memory.early-release (dropped guard: cancel-retains-permit)
  action cancelJobEarlyRelease(j: int): bool = all { h.running.contains(j), h' = h.with("running", h.running.exclude(Set(j))).with("cleanup", h.cleanup.union(Set(j))).with("admitted", h.admitted.exclude(Set(j))) }
  action stepEarlyRelease = any { step, { nondet j = jobs.oneOf()
    cancelJobEarlyRelease(j) } }
  // Countermodel engineering.concurrency.backpressure-memory.over-admit (dropped guard: admit-capacity-bound)
  action admitJobOverCapacity(j: int): bool = all { (not(owners.contains(j)) and not(h.done.contains(j))), true, size(h.queued) < h.queueLimit, h' = h.with("admitted", h.admitted.union(Set(j))).with("queued", h.queued.union(Set(j))) }
  action stepOverAdmit = any { step, { nondet j = jobs.oneOf()
    admitJobOverCapacity(j) } }
  // Countermodel engineering.concurrency.backpressure-memory.queue-overflow (dropped guard: admit-queue-bound)
  action admitJobQueueOverflow(j: int): bool = all { (not(owners.contains(j)) and not(h.done.contains(j))), size(h.admitted) < h.limit, true, h' = h.with("admitted", h.admitted.union(Set(j))).with("queued", h.queued.union(Set(j))) }
  action stepQueueOverflow = any { step, { nondet j = jobs.oneOf()
    admitJobQueueOverflow(j) } }
  // Countermodel engineering.concurrency.backpressure-memory.duplicate-admit (dropped guard: admit-disjoint-job)
  action admitJobDuplicate(j: int): bool = all { true, size(h.admitted) < h.limit, size(h.queued) < h.queueLimit, h' = h.with("admitted", h.admitted.union(Set(j))).with("queued", h.queued.union(Set(j))) }
  action stepDuplicateAdmit = any { step, { nondet j = jobs.oneOf()
    admitJobDuplicate(j) } }
  run validLifecycleTest = init.then(admitJob(0)).then(startJob(0)).then(finishJob(0)).then(drainJob(0)).then(all { assert(safety), assert(size(h.done) == 1), assert(size(h.admitted) == 0), h' = h })
  run cancelCleanupTest = init.then(admitJob(0)).then(startJob(0)).then(cancelJob(0)).then(all { assert(safety), assert(size(h.cleanup) == 1), assert(h.cleanup.subseteq(h.admitted)), h' = h }).then(cleanJob(0)).then(all { assert(safety), assert(size(h.done) == 1), h' = h })
  run earlyReleaseViolatesSafetyTest = init.then(admitJob(0)).then(startJob(0)).then(cancelJobEarlyRelease(0)).then(all { assert(not(safety)), assert(size(h.cleanup) > 0), assert(not(h.cleanup.subseteq(h.admitted))), h' = h })
  run overAdmitViolatesSafetyTest = init.then(admitJob(0)).then(startJob(0)).then(admitJob(1)).then(startJob(1)).then(admitJobOverCapacity(2)).then(all { assert(not(safety)), assert(size(h.admitted) > h.limit), h' = h })
  run queueOverflowViolatesSafetyTest = init.then(admitJob(0)).then(admitJobQueueOverflow(1)).then(all { assert(not(safety)), assert(size(h.queued) > h.queueLimit), h' = h })
  run duplicateAdmitViolatesSafetyTest = init.then(admitJob(0)).then(startJob(0)).then(admitJobDuplicate(0)).then(all { assert(not(safety)), assert(size(h.queued.intersect(h.running)) > 0), h' = h })
}
