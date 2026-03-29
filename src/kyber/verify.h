#ifndef KYBER_VERIFY_H
#define KYBER_VERIFY_H

#include <stdint.h>
#include <stddef.h>

/* Constant-time comparison. Returns 0 if equal, 1 otherwise. */
int kyber_verify(const uint8_t *a, const uint8_t *b, size_t len);

/* Constant-time conditional move: copy src to dst if b==1 */
void kyber_cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b);

#endif
