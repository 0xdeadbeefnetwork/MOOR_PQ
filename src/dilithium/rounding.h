#ifndef DILITHIUM_ROUNDING_H
#define DILITHIUM_ROUNDING_H

#include <stdint.h>
#include "params.h"

int32_t dilithium_power2round(int32_t *a0, int32_t a);
int32_t dilithium_decompose(int32_t *a0, int32_t a);
unsigned int dilithium_make_hint(int32_t a0, int32_t a1);
int32_t dilithium_use_hint(int32_t a, unsigned int hint);

#endif
