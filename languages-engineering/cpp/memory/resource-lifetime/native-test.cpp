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
  return 0;
}
