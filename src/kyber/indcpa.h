#ifndef KYBER_INDCPA_H
#define KYBER_INDCPA_H

#include <stdint.h>
#include "params.h"

void kyber_indcpa_keypair(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                           uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);

void kyber_indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                       const uint8_t m[KYBER_INDCPA_MSGBYTES],
                       const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                       const uint8_t rand_bytes[KYBER_SYMBYTES]);

void kyber_indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                       const uint8_t c[KYBER_INDCPA_BYTES],
                       const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);

#endif
