/*
 * MOOR -- Proof-of-Work relay admission (Argon2id memory-hard)
 */
#ifndef MOOR_POW_H
#define MOOR_POW_H

#include <stdint.h>

/*
 * Solve a PoW puzzle: find nonce where Argon2id(nonce||timestamp, salt=BLAKE2b-128(identity_pk))
 * has `difficulty` leading zero bits.
 * memlimit: Argon2id memory in bytes (0 = use MOOR_POW_MEMLIMIT_DEFAULT).
 * Returns 0 on success with nonce_out and timestamp_out set.
 */
int moor_pow_solve(uint64_t *nonce_out, uint64_t *timestamp_out,
                   const uint8_t identity_pk[32], int difficulty,
                   uint32_t memlimit);

/*
 * Verify a PoW solution.
 * memlimit: must match the value used by the solver.
 * Returns 0 if valid (correct leading zeros and timestamp within window).
 */
int moor_pow_verify(const uint8_t identity_pk[32],
                    uint64_t nonce, uint64_t timestamp, int difficulty,
                    uint32_t memlimit);

/*
 * HS PoW: client solves puzzle before INTRODUCE1.
 * Puzzle: Argon2id(service_pk||nonce, salt=seed[0..15]) must have `difficulty` leading zero bits.
 * No timestamp -- freshness tied to seed rotation by the HS.
 * memlimit: Argon2id memory in bytes (0 = use MOOR_POW_MEMLIMIT_DEFAULT).
 */
int moor_pow_solve_hs(uint64_t *nonce_out, const uint8_t seed[32],
                      const uint8_t service_pk[32], int difficulty,
                      uint32_t memlimit);
int moor_pow_verify_hs(const uint8_t seed[32], const uint8_t service_pk[32],
                       uint64_t nonce, int difficulty,
                       uint32_t memlimit);

#endif /* MOOR_POW_H */
