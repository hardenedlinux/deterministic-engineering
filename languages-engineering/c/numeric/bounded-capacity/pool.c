#include "capacity.h"

/* A pool uses the same checked arithmetic, with different caller semantics. */
int pool_fits(uint32_t retained, uint32_t incoming, uint32_t budget)
{
  uint32_t total = 0;
  return capacity_total(retained, incoming, &total) && total <= budget;
}
