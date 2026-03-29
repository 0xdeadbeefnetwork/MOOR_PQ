#ifndef DILITHIUM_PACKING_H
#define DILITHIUM_PACKING_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

void dilithium_pack_pk(uint8_t pk[DILITHIUM_CRYPTO_PUBLICKEYBYTES],
                       const uint8_t rho[DILITHIUM_SEEDBYTES],
                       const dilithium_polyveck *t1);

void dilithium_pack_sk(uint8_t sk[DILITHIUM_CRYPTO_SECRETKEYBYTES],
                       const uint8_t rho[DILITHIUM_SEEDBYTES],
                       const uint8_t tr[DILITHIUM_TRBYTES],
                       const uint8_t key[DILITHIUM_SEEDBYTES],
                       const dilithium_polyvecl *s1,
                       const dilithium_polyveck *s2,
                       const dilithium_polyveck *t0);

void dilithium_pack_sig(uint8_t sig[DILITHIUM_CRYPTO_BYTES],
                        const uint8_t c[DILITHIUM_CTILDEBYTES],
                        const dilithium_polyvecl *z,
                        const dilithium_polyveck *h);

void dilithium_unpack_pk(uint8_t rho[DILITHIUM_SEEDBYTES],
                         dilithium_polyveck *t1,
                         const uint8_t pk[DILITHIUM_CRYPTO_PUBLICKEYBYTES]);

void dilithium_unpack_sk(uint8_t rho[DILITHIUM_SEEDBYTES],
                         uint8_t tr[DILITHIUM_TRBYTES],
                         uint8_t key[DILITHIUM_SEEDBYTES],
                         dilithium_polyvecl *s1,
                         dilithium_polyveck *s2,
                         dilithium_polyveck *t0,
                         const uint8_t sk[DILITHIUM_CRYPTO_SECRETKEYBYTES]);

int dilithium_unpack_sig(uint8_t c[DILITHIUM_CTILDEBYTES],
                         dilithium_polyvecl *z,
                         dilithium_polyveck *h,
                         const uint8_t sig[DILITHIUM_CRYPTO_BYTES]);

#endif
