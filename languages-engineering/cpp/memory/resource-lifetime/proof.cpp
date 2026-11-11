// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "slot.hpp"

extern bool nondet_bool();

void lifetime_harness()
{
  unsigned live = 0;
  {
    ResourceSlot original(&live);
    __CPROVER_assert(live == 1 && original.owns(), "owner.acquired");
    {
      ResourceSlot moved;
      bool transferred = original.transfer_to(moved);
      __CPROVER_assert(transferred && live == 1 && moved.owns() && !original.owns(),
                       "owner.unique-after-transfer");
      __CPROVER_assert(!original.transfer_to(moved) && live == 1 && moved.owns(),
                       "owner.occupied-refusal");
      if (nondet_bool())
        moved.reset();
      moved.reset();
      __CPROVER_assert(live == 0 && !moved.owns(), "owner.idempotent-release");
    }
    __CPROVER_assert(live == 0, "owner.inner-destruction");
  }
  __CPROVER_assert(live == 0, "owner.outer-destruction");

  unsigned source_live = 0;
  unsigned destination_live = 0;
  {
    ResourceSlot source(&source_live);
    ResourceSlot destination(&destination_live);
    __CPROVER_assert(!source.transfer_to(destination) &&
                       source.owns() && destination.owns() &&
                       source_live == 1 && destination_live == 1,
                     "owner.occupied-preserves-both");
    __CPROVER_assert(!source.transfer_to(source) &&
                       source.owns() && source_live == 1,
                     "owner.self-refusal");
  }
  __CPROVER_assert(source_live == 0 && destination_live == 0,
                   "owner.distinct-counter-destruction");

  ResourceSlot empty_source;
  ResourceSlot empty_destination;
  __CPROVER_assert(empty_source.transfer_to(empty_destination) &&
                     !empty_source.owns() && !empty_destination.owns(),
                   "owner.empty-transfer");
}
