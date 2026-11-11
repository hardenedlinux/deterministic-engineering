#include "capacity.h"

/* A parser admits a payload only after accounting for its framing bytes. */
int parser_fits(uint32_t payload, uint32_t header, uint32_t available)
{
  uint32_t total = 0;
  return capacity_total(payload, header, &total) && total <= available;
}
