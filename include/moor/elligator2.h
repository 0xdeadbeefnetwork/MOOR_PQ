/*
 * MOOR -- Elligator2 for Curve25519
 *
 * Direct and inverse maps for encoding Curve25519 public keys as
 * uniformly random 32-byte representatives.
 *
 * Based on:
 *   Bernstein, Hamburg, Krasnova, Lange. "Elligator: Elliptic-curve
 *   points indistinguishable from uniform random strings" (2013).
 *   http://elligator.cr.yp.to/elligator-20130828.pdf
 *
 * Reference implementation: github.com/Kleshni/Elligator-2
 *
 * Constants:
 *   p = 2^255 - 19           (field prime)
 *   A = 486662               (Montgomery curve parameter)
 *   u = 2                    (non-square in F_p, Elligator parameter)
 *
 * All field arithmetic is constant-time (no branches on secret data).
 */
#ifndef MOOR_ELLIGATOR2_H
#define MOOR_ELLIGATOR2_H

#include <stdint.h>

/*
 * Check if a Curve25519 public key (Montgomery u-coordinate) is
 * Elligator2-representable (~50% of points are).
 *
 * Returns 1 if representable, 0 if not.
 */
int moor_elligator2_is_representable(const uint8_t pk[32]);

/*
 * Compute the Elligator2 representative for a representable Curve25519 key.
 * The representative is indistinguishable from 32 uniform random bytes.
 *
 * high_y selects between the two possible representatives for the same point.
 * Pass a random bit for full uniformity.
 *
 * Returns 0 on success, -1 if not representable.
 */
int moor_elligator2_key_to_representative(uint8_t representative[32],
                                          const uint8_t pk[32],
                                          int high_y);

/*
 * Recover the Curve25519 public key from an Elligator2 representative.
 * This is the "direct map" -- always succeeds.
 *
 * The high_y value is written to *high_y_out if non-NULL.
 */
void moor_elligator2_representative_to_key(uint8_t pk[32],
                                           const uint8_t representative[32]);

/*
 * Generate an Elligator2-representable Curve25519 keypair.
 *
 * Uses rejection sampling: generates random keypairs until one is
 * representable, then computes the representative.
 *
 * Outputs:
 *   pk[32]             - Curve25519 public key
 *   sk[32]             - Curve25519 secret key
 *   representative[32] - Elligator2 representative (uniform random bytes)
 *
 * Returns 0 on success (always succeeds; expected ~2 iterations).
 */
int moor_elligator2_keygen(uint8_t pk[32], uint8_t sk[32],
                           uint8_t representative[32]);

#endif /* MOOR_ELLIGATOR2_H */
