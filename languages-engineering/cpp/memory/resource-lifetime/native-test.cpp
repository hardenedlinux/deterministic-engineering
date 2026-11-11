// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "slot.hpp"
#include <cassert>

int main()
{
  unsigned live = 0;
  {
    ResourceSlot first(&live);
    assert(live == 1 && first.owns());
    {
      ResourceSlot second;
      assert(first.transfer_to(second));
      assert(live == 1 && second.owns() && !first.owns());
      assert(!first.transfer_to(second));
    }
    assert(live == 0);
    first.reset();
    assert(live == 0);
  }
  assert(live == 0);
  unsigned source_live = 0;
  unsigned destination_live = 0;
  {
    ResourceSlot source(&source_live);
    ResourceSlot destination(&destination_live);
    assert(!source.transfer_to(destination));
    assert(source.owns() && destination.owns());
    assert(source_live == 1 && destination_live == 1);
    assert(!source.transfer_to(source));
    assert(source.owns() && source_live == 1);
  }
  assert(source_live == 0 && destination_live == 0);

  ResourceSlot empty_source;
  ResourceSlot empty_destination;
  assert(empty_source.transfer_to(empty_destination));
  assert(!empty_source.owns() && !empty_destination.owns());
  return 0;
}
