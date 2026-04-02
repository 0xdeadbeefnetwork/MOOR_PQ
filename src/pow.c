/*
 * MOOR -- Proof-of-Work relay admission (Argon2id memory-hard)
 *
 * Replaces BLAKE2b hashcash with Argon2id from libsodium.
 * Each hash requires ~256KB of memory, equalizing CPU/GPU cost.
 */
#include "moor/moor.h"
#include <sodium.h>
#include <string.h>
#include <time.h>

/* ---------- Nonce replay cache ----------
 * Bounded hash set of recently-verified (nonce, timestamp) pairs.
 * Prevents solving once and replaying within the timestamp window.
 */
#define POW_NONCE_CACHE_SIZE 4096

typedef struct {
    uint64_t nonce;
    uint64_t timestamp;
    uint64_t insert_time;
    uint64_t context_hash; /* hash of identity_pk to avoid cross-identity collision */
} pow_nonce_entry_t;

static pow_nonce_entry_t g_nonce_cache[POW_NONCE_CACHE_SIZE];
static int g_nonce_cache_init = 0;

/* Secret key folded into cache slot hash to prevent attacker-controlled
 * collision attacks (all other hash inputs are publicly visible). */
static uint8_t g_nonce_cache_secret[32];
static int g_nonce_cache_secret_init = 0;

static void nonce_cache_ensure_init(void) {
    if (!g_nonce_cache_init) {
        memset(g_nonce_cache, 0, sizeof(g_nonce_cache));
        g_nonce_cache_init = 1;
    }
    if (!g_nonce_cache_secret_init) {
        randombytes_buf(g_nonce_cache_secret, sizeof(g_nonce_cache_secret));
        g_nonce_cache_secret_init = 1;
    }
}

/* Returns 1 if (nonce, timestamp, ctx) was already seen, 0 if new (inserts it) */
static int nonce_cache_check_and_insert(uint64_t nonce, uint64_t timestamp,
                                        uint64_t ctx) {
    nonce_cache_ensure_init();
    uint64_t now = (uint64_t)time(NULL);

    /* Hash to slot — include context to separate different identities,
     * and fold in a secret key so attackers cannot predict slot placement. */
    uint64_t secret_word;
    memcpy(&secret_word, g_nonce_cache_secret, 8);
    uint64_t h = nonce ^ (timestamp * 2654435761ULL) ^ (ctx * 0x9E3779B97F4A7C15ULL) ^ secret_word;
    uint32_t slot = (uint32_t)(h % POW_NONCE_CACHE_SIZE);

    /* Linear probe up to 8 slots */
    for (int probe = 0; probe < 8; probe++) {
        uint32_t idx = (slot + probe) % POW_NONCE_CACHE_SIZE;
        pow_nonce_entry_t *e = &g_nonce_cache[idx];

        /* Expired entry — evict */
        if (e->insert_time != 0 &&
            now > e->insert_time + MOOR_POW_TIMESTAMP_WINDOW + 60) {
            e->insert_time = 0;
        }

        /* Empty slot — insert */
        if (e->insert_time == 0) {
            e->nonce = nonce;
            e->timestamp = timestamp;
            e->context_hash = ctx;
            e->insert_time = now;
            return 0; /* new */
        }

        /* Match — replay detected (same identity + nonce + timestamp) */
        if (e->nonce == nonce && e->timestamp == timestamp &&
            e->context_hash == ctx)
            return 1; /* seen */
    }

    /* All probe slots full — evict oldest and insert */
    uint32_t oldest_idx = slot;
    uint64_t oldest_time = g_nonce_cache[slot].insert_time;
    for (int probe = 1; probe < 8; probe++) {
        uint32_t idx = (slot + probe) % POW_NONCE_CACHE_SIZE;
        if (g_nonce_cache[idx].insert_time < oldest_time) {
            oldest_time = g_nonce_cache[idx].insert_time;
            oldest_idx = idx;
        }
    }
    g_nonce_cache[oldest_idx].nonce = nonce;
    g_nonce_cache[oldest_idx].timestamp = timestamp;
    g_nonce_cache[oldest_idx].context_hash = ctx;
    g_nonce_cache[oldest_idx].insert_time = now;
    return 0; /* new (evicted oldest) */
}

/* HS PoW nonce replay cache — keyed by seed to handle seed rotation */
static pow_nonce_entry_t g_hs_nonce_cache[POW_NONCE_CACHE_SIZE];
static int g_hs_nonce_cache_init = 0;

/* HS PoW replay check: bind nonce to seed+service_pk so a valid PoW for
 * one seed rotation or intro point cannot be replayed elsewhere (CWE-331). */
static int hs_nonce_cache_check_and_insert(uint64_t nonce,
                                           uint64_t seed_hash,
                                           uint64_t service_hash) {
    if (!g_hs_nonce_cache_init) {
        memset(g_hs_nonce_cache, 0, sizeof(g_hs_nonce_cache));
        g_hs_nonce_cache_init = 1;
    }
    uint64_t now = (uint64_t)time(NULL);
    uint64_t ctx = seed_hash ^ (service_hash * 0x9E3779B97F4A7C15ULL);
    uint64_t h = nonce ^ (ctx * 2654435761ULL);
    uint32_t slot = (uint32_t)(h % POW_NONCE_CACHE_SIZE);

    for (int probe = 0; probe < 8; probe++) {
        uint32_t idx = (slot + probe) % POW_NONCE_CACHE_SIZE;
        pow_nonce_entry_t *e = &g_hs_nonce_cache[idx];

        /* Expire after 1 hour (seed rotation interval) */
        if (e->insert_time != 0 && now > e->insert_time + 3600) {
            e->insert_time = 0;
        }
        if (e->insert_time == 0) {
            e->nonce = nonce;
            e->context_hash = ctx;
            e->insert_time = now;
            return 0;
        }
        if (e->nonce == nonce && e->context_hash == ctx)
            return 1; /* replay */
    }

    /* Evict oldest */
    uint32_t oldest_idx = slot;
    uint64_t oldest_time = g_hs_nonce_cache[slot].insert_time;
    for (int probe = 1; probe < 8; probe++) {
        uint32_t idx = (slot + probe) % POW_NONCE_CACHE_SIZE;
        if (g_hs_nonce_cache[idx].insert_time < oldest_time) {
            oldest_time = g_hs_nonce_cache[idx].insert_time;
            oldest_idx = idx;
        }
    }
    g_hs_nonce_cache[oldest_idx].nonce = nonce;
    g_hs_nonce_cache[oldest_idx].context_hash = ctx;
    g_hs_nonce_cache[oldest_idx].insert_time = now;
    return 0;
}

/* Check if hash has at least `bits` leading zero bits */
static int has_leading_zeros(const uint8_t *hash, int hashlen, int bits) {
    if (bits <= 0) return (bits == 0) ? 1 : 0;
    if (bits > hashlen * 8) return 0;
    int full_bytes = bits / 8;
    int remaining_bits = bits % 8;

    for (int i = 0; i < full_bytes && i < hashlen; i++) {
        if (hash[i] != 0)
            return 0;
    }

    if (remaining_bits > 0 && full_bytes < hashlen) {
        uint8_t mask = (uint8_t)(0xFF << (8 - remaining_bits));
        if ((hash[full_bytes] & mask) != 0)
            return 0;
    }

    return 1;
}

/* Resolve memlimit: 0 → default */
static uint32_t resolve_memlimit(uint32_t memlimit) {
    if (memlimit == 0) return MOOR_POW_MEMLIMIT_DEFAULT;
    if (memlimit < MOOR_POW_MEMLIMIT_MIN) return MOOR_POW_MEMLIMIT_MIN;
    if (memlimit > MOOR_POW_MEMLIMIT_MAX) return MOOR_POW_MEMLIMIT_MAX;
    return memlimit;
}

/*
 * Relay PoW:
 *   epoch = floor(timestamp / MOOR_POW_TIMESTAMP_WINDOW)
 *   salt = BLAKE2b-128(identity_pk || epoch)  (16 bytes, epoch-bound)
 *   passwd = nonce(8) || timestamp(8) (16 bytes)
 *   hash = Argon2id(passwd, salt, opslimit=1, memlimit)
 *
 * Fix CWE-330: Mix a time-based epoch into the salt so that solutions
 * cannot be precomputed from the publicly-known identity_pk alone.
 * Solutions are only valid within the epoch derived from their timestamp.
 */

/* Derive epoch-bound salt: BLAKE2b-128(identity_pk(32) || epoch(8)) */
static void derive_epoch_salt(uint8_t salt[crypto_pwhash_SALTBYTES],
                              uint8_t salt_full_out[32],
                              const uint8_t identity_pk[32],
                              uint64_t epoch) {
    uint8_t preimage[40]; /* identity_pk(32) + epoch(8) */
    memcpy(preimage, identity_pk, 32);
    /* Big-endian encoding for cross-platform consistency (CWE-330) */
    for (int i = 7; i >= 0; i--)
        preimage[32 + (7 - i)] = (uint8_t)(epoch >> (i * 8));
    uint8_t hash[32];
    moor_crypto_hash(hash, preimage, sizeof(preimage));
    memcpy(salt, hash, crypto_pwhash_SALTBYTES);
    if (salt_full_out)
        memcpy(salt_full_out, hash, 32);
    sodium_memzero(preimage, sizeof(preimage));
}

int moor_pow_solve(uint64_t *nonce_out, uint64_t *timestamp_out,
                   const uint8_t identity_pk[32], int difficulty,
                   uint32_t memlimit) {
    if (!nonce_out || !timestamp_out || !identity_pk || difficulty < 0 || difficulty > 64)
        return -1;

    memlimit = resolve_memlimit(memlimit);

    uint64_t timestamp = (uint64_t)time(NULL);
    *timestamp_out = timestamp;

    /* Derive epoch-bound salt: ties solution to current time window */
    uint64_t epoch = timestamp / MOOR_POW_TIMESTAMP_WINDOW;
    uint8_t salt[crypto_pwhash_SALTBYTES]; /* 16 bytes */
    derive_epoch_salt(salt, NULL, identity_pk, epoch);

    /* passwd = nonce(8) || timestamp(8) */
    uint8_t passwd[16];
    memcpy(passwd + 8, &timestamp, 8);

    uint8_t hash[32];
    uint64_t nonce = 0;
    int shift = (difficulty < 24) ? difficulty + 4 : 28;
    if (shift < 0) shift = 0;
    if (shift > 63) shift = 63;
    uint64_t max_iters = (1ULL << shift);

    for (uint64_t iter = 0; iter < max_iters; iter++) {
        memcpy(passwd, &nonce, 8);

        if (crypto_pwhash(hash, 32, (const char *)passwd, sizeof(passwd),
                          salt, MOOR_POW_OPSLIMIT, memlimit,
                          crypto_pwhash_ALG_ARGON2ID13) != 0)
            return -1;

        if (has_leading_zeros(hash, 32, difficulty)) {
            *nonce_out = nonce;
            sodium_memzero(hash, sizeof(hash));
            return 0;
        }
        nonce++;
        if (nonce == 0)
            return -1;
    }
    return -1; /* exceeded max iterations */
}

int moor_pow_verify(const uint8_t identity_pk[32],
                    uint64_t nonce, uint64_t timestamp, int difficulty,
                    uint32_t memlimit) {
    if (!identity_pk || difficulty < 0 || difficulty > 64)
        return -1;

    memlimit = resolve_memlimit(memlimit);

    if (difficulty == 0)
        return 0; /* PoW disabled */

    /* Check timestamp freshness */
    uint64_t now = (uint64_t)time(NULL);
    if (timestamp > now + 60)
        return -1;
    if (now > timestamp && (now - timestamp) > MOOR_POW_TIMESTAMP_WINDOW)
        return -1;

    /* Fix CWE-330: Derive epoch-bound salt from the solution's timestamp.
     * The epoch is floor(timestamp / WINDOW), so the salt changes every epoch.
     * Accept both current and previous epoch to handle boundary transitions
     * (client solves near end of epoch N, server verifies in epoch N+1). */
    uint64_t solution_epoch = timestamp / MOOR_POW_TIMESTAMP_WINDOW;
    uint64_t current_epoch  = now / MOOR_POW_TIMESTAMP_WINDOW;

    /* Only accept solution's epoch if it matches current or previous epoch */
    if (solution_epoch != current_epoch && solution_epoch + 1 != current_epoch) {
        return -1; /* epoch too old */
    }

    uint8_t salt_full[32];
    uint8_t salt[crypto_pwhash_SALTBYTES];
    derive_epoch_salt(salt, salt_full, identity_pk, solution_epoch);

    /* passwd = nonce(8) || timestamp(8) */
    uint8_t passwd[16];
    memcpy(passwd, &nonce, 8);
    memcpy(passwd + 8, &timestamp, 8);

    uint8_t hash[32];
    if (crypto_pwhash(hash, 32, (const char *)passwd, sizeof(passwd),
                      salt, MOOR_POW_OPSLIMIT, memlimit,
                      crypto_pwhash_ALG_ARGON2ID13) != 0)
        return -1;

    int ok = has_leading_zeros(hash, 32, difficulty) ? 0 : -1;
    sodium_memzero(hash, sizeof(hash));

    /* Fix #177: Check replay cache AFTER hash verification succeeds.
     * Inserting before verification allows attackers to poison the cache
     * with invalid PoW, causing legitimate solutions to be rejected. */
    if (ok == 0) {
        uint64_t ctx;
        memcpy(&ctx, salt_full, 8);
        if (nonce_cache_check_and_insert(nonce, timestamp, ctx))
            return -1; /* valid PoW but replayed nonce */
    }
    return ok;
}

/*
 * HS PoW:
 *   salt = seed[0..15]  (first 16 bytes of seed)
 *   passwd = service_pk(32) || nonce(8) (40 bytes)
 *   hash = Argon2id(passwd, salt, opslimit=1, memlimit)
 */
int moor_pow_solve_hs(uint64_t *nonce_out, const uint8_t seed[32],
                      const uint8_t service_pk[32], int difficulty,
                      uint32_t memlimit) {
    if (!nonce_out || !seed || !service_pk || difficulty < 0 || difficulty > 64)
        return -1;

    memlimit = resolve_memlimit(memlimit);

    /* Salt = first 16 bytes of seed */
    uint8_t salt[crypto_pwhash_SALTBYTES];
    memcpy(salt, seed, sizeof(salt));

    /* passwd = service_pk(32) || nonce(8) */
    uint8_t passwd[40];
    memcpy(passwd, service_pk, 32);

    uint8_t hash[32];
    uint64_t nonce = 0;
    int shift = (difficulty < 24) ? difficulty + 4 : 28;
    if (shift < 0) shift = 0;
    if (shift > 63) shift = 63;
    uint64_t max_iters = (1ULL << shift);

    for (uint64_t iter = 0; iter < max_iters; iter++) {
        memcpy(passwd + 32, &nonce, 8);

        if (crypto_pwhash(hash, 32, (const char *)passwd, sizeof(passwd),
                          salt, MOOR_POW_OPSLIMIT, memlimit,
                          crypto_pwhash_ALG_ARGON2ID13) != 0)
            return -1;

        if (has_leading_zeros(hash, 32, difficulty)) {
            *nonce_out = nonce;
            sodium_memzero(hash, sizeof(hash));
            return 0;
        }
        nonce++;
        if (nonce == 0)
            return -1;
    }
    return -1; /* exceeded max iterations */
}

int moor_pow_verify_hs(const uint8_t seed[32], const uint8_t service_pk[32],
                       uint64_t nonce, int difficulty,
                       uint32_t memlimit) {
    if (!seed || !service_pk || difficulty < 0 || difficulty > 64)
        return -1;

    if (difficulty == 0)
        return 0; /* PoW disabled -- always accept */

    memlimit = resolve_memlimit(memlimit);

    uint8_t salt[crypto_pwhash_SALTBYTES];
    memcpy(salt, seed, sizeof(salt));

    uint8_t passwd[40];
    memcpy(passwd, service_pk, 32);
    memcpy(passwd + 32, &nonce, 8);

    uint8_t hash[32];
    if (crypto_pwhash(hash, 32, (const char *)passwd, sizeof(passwd),
                      salt, MOOR_POW_OPSLIMIT, memlimit,
                      crypto_pwhash_ALG_ARGON2ID13) != 0)
        return -1;

    int ok = has_leading_zeros(hash, 32, difficulty) ? 0 : -1;
    sodium_memzero(hash, sizeof(hash));

    /* Fix #177: Check replay cache AFTER verification (same as relay PoW).
     * Bind to seed + service_pk to prevent cross-identity/cross-seed replay. */
    if (ok == 0) {
        uint64_t seed_h, svc_h;
        memcpy(&seed_h, seed, 8);
        memcpy(&svc_h, service_pk, 8);
        if (hs_nonce_cache_check_and_insert(nonce, seed_h, svc_h))
            return -1;
    }
    return ok;
}
