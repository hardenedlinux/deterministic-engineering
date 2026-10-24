import Std

namespace RustResources

-- Conditional accounting only. Source/size/ownership premises are external.
def retained (queued active item fixed cache : Nat) : Nat :=
  (queued + active) * item + fixed + cache

theorem capacity_monotone (q a b item fixed cache : Nat) (h : a ≤ b) :
    retained q a item fixed cache ≤ retained q b item fixed cache := by
  exact Nat.add_le_add_right
    (Nat.add_le_add_right (Nat.mul_le_mul_right item (Nat.add_le_add_left h q)) fixed) cache

theorem budget_reuse (old new budget : Nat) (smaller : new ≤ old)
    (checked : old ≤ budget) : new ≤ budget := Nat.le_trans smaller checked

example : retained 2 2 64 128 0 = 384 := by decide
example : retained 2 4 64 128 0 = 512 := by decide
example : retained 2 2 64 128 128 = 512 := by decide
-- Dropping a future is not a premise that the job's retained allocation is zero.
example : ¬ retained 2 4 64 128 128 ≤ 512 := by decide

end RustResources
