/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

/-!
# DeterministicEngineering.Core.Containment

Unbounded parametric containment theorems over arbitrary-depth finite trees
(10.154 Layer A shared mathematical foundation).

Complements Quint's bounded finite interleaving checks (zero duplication):
Quint explores 2-grandchild fault races and generates MBT ITF traces;
this module proves arbitrary-depth (`∀ d, k`) tree containment closure and
crash/SIGKILL fate-sharing.
-/

namespace DeterministicEngineering.Core.Containment

/-- Arbitrary-depth finite ownership tree (e.g., process tree or capability delegation tree). -/
inductive OwnershipTree (Cid : Type) where
  | node (id : Nat) (cid : Cid) (alive : Bool) (children : List (OwnershipTree Cid))

/-- Every node at every depth belongs to container `target` (SpawnPreservesContainer invariant). -/
def containerClosed {Cid : Type} (target : Cid) : OwnershipTree Cid → Prop
  | .node _ cid _ children =>
      cid = target ∧ ∀ child ∈ children, containerClosed target child

/-- Every node at every depth is terminated (zero orphans / zero residual descendants). -/
def allDead {Cid : Type} : OwnershipTree Cid → Prop
  | .node _ _ alive children =>
      alive = false ∧ ∀ child ∈ children, allDead child

/-- Atomic kernel container termination (`cgroup.kill`, PID namespace exit, or fate-shared tree kill). -/
def killContainer {Cid : Type} [DecidableEq Cid] (target : Cid) : OwnershipTree Cid → OwnershipTree Cid
  | .node id cid alive children =>
      .node id cid (if cid = target then false else alive)
            (children.map (killContainer target))

/-- Non-cooperative single-PID `SIGKILL` on the root node only (models the `GatewayGuard::drop` bug). -/
def sigkillRootOnly {Cid : Type} : OwnershipTree Cid → OwnershipTree Cid
  | .node id cid _ children =>
      .node id cid false children

/-- Unbounded structural induction theorem: for any tree depth and arbitrary branching factor,
if `containerClosed target t` holds, atomic `killContainer target t` leaves zero live descendants. -/
theorem killContainer_allDead_of_closed {Cid : Type} [DecidableEq Cid]
    (target : Cid) : ∀ t : OwnershipTree Cid,
    containerClosed target t → allDead (killContainer target t)
  | .node id cid alive children, hClosed => by
      unfold containerClosed at hClosed
      rcases hClosed with ⟨hCid, hChildren⟩
      simp only [killContainer, allDead]
      constructor
      · simp [hCid]
      · intro child hMem
        rcases List.mem_map.mp hMem with ⟨orig, hOrigMem, rfl⟩
        exact killContainer_allDead_of_closed target orig (hChildren orig hOrigMem)

/-- Abrupt root `SIGKILL` preserves container membership of the whole subtree. -/
theorem sigkillRootOnly_preserves_closed {Cid : Type}
    (target : Cid) : ∀ t : OwnershipTree Cid,
    containerClosed target t → containerClosed target (sigkillRootOnly t)
  | .node _ _ _ _, hClosed => by
      simpa [sigkillRootOnly, containerClosed] using hClosed

/-- Crash/SIGKILL fate-sharing theorem: even after an intermediate supervisor is abruptly
`SIGKILL`ed (`sigkillRootOnly`), firing `killContainer` still leaves zero live nodes at any depth. -/
theorem crashSafe_killContainer_after_root_sigkill {Cid : Type} [DecidableEq Cid]
    (target : Cid) (t : OwnershipTree Cid) (hClosed : containerClosed target t) :
    allDead (killContainer target (sigkillRootOnly t)) :=
  killContainer_allDead_of_closed target (sigkillRootOnly t)
    (sigkillRootOnly_preserves_closed target t hClosed)

/-- Negative witness: single-PID `SIGKILL` on a supervisor with a live child strands an orphan. -/
theorem singlePidKill_strands_live_child :
    ¬ allDead (sigkillRootOnly
      (OwnershipTree.node 1 (0 : Nat) true [OwnershipTree.node 2 0 true []])) := by
  intro hDead
  simp only [sigkillRootOnly, allDead] at hDead
  rcases hDead with ⟨_, hChildren⟩
  have hChild := hChildren (OwnershipTree.node 2 0 true []) (by simp)
  simp only [allDead] at hChild
  exact Bool.noConfusion hChild.1

end DeterministicEngineering.Core.Containment
