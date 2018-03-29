#ifndef SEC_H
#define SEC_H

#include <inttypes.h>
#include "parameter.h"

uint8_t parity(uint16_t x);

uint32_t SEC_encode(uint16_t x);
uint16_t SEC_decode(uint32_t c);

#endif