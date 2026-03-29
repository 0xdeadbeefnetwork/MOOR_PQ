#ifndef KYBER_CBD_H
#define KYBER_CBD_H

#include <stdint.h>
#include "poly.h"

void kyber_cbd_eta1(kyber_poly *r, const uint8_t buf[KYBER_ETA1*KYBER_N/4]);
void kyber_cbd_eta2(kyber_poly *r, const uint8_t buf[KYBER_ETA2*KYBER_N/4]);

#endif
