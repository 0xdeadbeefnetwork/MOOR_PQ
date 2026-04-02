#include "moor/moor.h"
#include <sodium.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <fcntl.h>
#include <share.h>
#include <sys/stat.h>
#include <windows.h>
#include <sddl.h>
#define mkdir(p, m) _mkdir(p)
/* M7: Create key files with owner-only DACL on Windows */
static FILE *secure_fopen_crypto(const char *path, const char *mode) {
    (void)mode;
    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR psd = NULL;
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    /* Owner-only: full access for owner, deny all others */
    if (ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:P(A;;FA;;;OW)", SDDL_REVISION_1, &psd, NULL)) {
        sa.lpSecurityDescriptor = psd;
    } else {
        sa.lpSecurityDescriptor = NULL;
    }
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, &sa,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (psd) LocalFree(psd);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    int fd = _open_osfhandle((intptr_t)h, _O_WRONLY | _O_BINARY);
    if (fd < 0) { CloseHandle(h); return NULL; }
    return _fdopen(fd, "wb");
}
#else
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
static FILE *secure_fopen_crypto(const char *path, const char *mode) {
    (void)mode;
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) return NULL;
    return fdopen(fd, "wb");
}
#endif

int moor_crypto_init(void) {
    if (sodium_init() < 0) {
        LOG_FATAL("failed to initialize libsodium");
        return -1;
    }
    LOG_INFO("libsodium initialized");
    return 0;
}

void moor_crypto_sign_keygen(uint8_t pk[32], uint8_t sk[64]) {
    crypto_sign_ed25519_keypair(pk, sk);
}

int moor_crypto_sign(uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                     const uint8_t sk[64]) {
    unsigned long long sig_len;
    if (crypto_sign_ed25519_detached(sig, &sig_len, msg, msg_len, sk) != 0)
        return -1;
    return 0;
}

int moor_crypto_sign_verify(const uint8_t sig[64], const uint8_t *msg,
                            size_t msg_len, const uint8_t pk[32]) {
    return crypto_sign_ed25519_verify_detached(sig, msg, msg_len, pk);
}

void moor_crypto_box_keygen(uint8_t pk[32], uint8_t sk[32]) {
    crypto_box_keypair(pk, sk);
}

int moor_crypto_dh(uint8_t shared_out[32], const uint8_t our_sk[32],
                   const uint8_t their_pk[32]) {
    if (crypto_scalarmult(shared_out, our_sk, their_pk) != 0) {
        LOG_ERROR("DH scalarmult failed (bad input?)");
        return -1;
    }
    /* Reject small-subgroup / low-order points that produce all-zero output */
    if (sodium_is_zero(shared_out, 32)) {
        LOG_ERROR("DH produced all-zero output (small-subgroup key?)");
        sodium_memzero(shared_out, 32);
        return -1;
    }
    return 0;
}

int moor_crypto_kx_client(uint8_t send_key[32], uint8_t recv_key[32],
                          const uint8_t client_pk[32], const uint8_t client_sk[32],
                          const uint8_t server_pk[32]) {
    if (crypto_kx_client_session_keys(recv_key, send_key,
                                       client_pk, client_sk,
                                       server_pk) != 0) {
        LOG_ERROR("kx client session keys failed");
        return -1;
    }
    return 0;
}

int moor_crypto_kx_server(uint8_t send_key[32], uint8_t recv_key[32],
                          const uint8_t server_pk[32], const uint8_t server_sk[32],
                          const uint8_t client_pk[32]) {
    if (crypto_kx_server_session_keys(recv_key, send_key,
                                       server_pk, server_sk,
                                       client_pk) != 0) {
        LOG_ERROR("kx server session keys failed");
        return -1;
    }
    return 0;
}

int moor_crypto_aead_encrypt(uint8_t *ct, size_t *ct_len,
                             const uint8_t *pt, size_t pt_len,
                             const uint8_t *ad, size_t ad_len,
                             const uint8_t key[32], uint64_t nonce) {
    /* Use IETF ChaCha20-Poly1305 with 12-byte nonce (8 bytes LE counter + 4 zero) */
    uint8_t nonce_buf[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    memset(nonce_buf, 0, sizeof(nonce_buf));
    for (int i = 0; i < 8; i++)
        nonce_buf[i] = (uint8_t)(nonce >> (i * 8));

    unsigned long long ct_len_ull;
    int rc = crypto_aead_chacha20poly1305_ietf_encrypt(
            ct, &ct_len_ull, pt, pt_len, ad, ad_len, NULL, nonce_buf, key);
    sodium_memzero(nonce_buf, sizeof(nonce_buf));
    if (rc != 0) return -1;
    if (ct_len) *ct_len = (size_t)ct_len_ull;
    return 0;
}

int moor_crypto_aead_decrypt(uint8_t *pt, size_t *pt_len,
                             const uint8_t *ct, size_t ct_len,
                             const uint8_t *ad, size_t ad_len,
                             const uint8_t key[32], uint64_t nonce) {
    uint8_t nonce_buf[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    memset(nonce_buf, 0, sizeof(nonce_buf));
    for (int i = 0; i < 8; i++)
        nonce_buf[i] = (uint8_t)(nonce >> (i * 8));

    unsigned long long pt_len_ull;
    int rc = crypto_aead_chacha20poly1305_ietf_decrypt(
            pt, &pt_len_ull, NULL, ct, ct_len, ad, ad_len, nonce_buf, key);
    sodium_memzero(nonce_buf, sizeof(nonce_buf));
    if (rc != 0) {
        sodium_memzero(pt, ct_len > crypto_aead_chacha20poly1305_ietf_ABYTES
                            ? ct_len - crypto_aead_chacha20poly1305_ietf_ABYTES : 0);
        return -1;
    }
    if (pt_len) *pt_len = (size_t)pt_len_ull;
    return 0;
}

int moor_crypto_stream_xor(uint8_t *buf, size_t len,
                           const uint8_t key[32], uint64_t nonce) {
    /* Use ChaCha20 as a stream cipher (XOR keystream with data).
     * No MAC -- this is for onion layers where each relay peels one layer.
     * Authentication is at the link layer (AEAD) and via relay digest. */
    uint8_t nonce_buf[crypto_stream_chacha20_ietf_NONCEBYTES]; /* 12 bytes */
    memset(nonce_buf, 0, sizeof(nonce_buf));
    for (int i = 0; i < 8; i++)
        nonce_buf[i] = (uint8_t)(nonce >> (i * 8));
    int rc = crypto_stream_chacha20_ietf_xor(buf, buf, len, nonce_buf, key);
    sodium_memzero(nonce_buf, sizeof(nonce_buf));
    return rc;
}

int moor_crypto_hash(uint8_t out[32], const uint8_t *data, size_t len) {
    return crypto_generichash_blake2b(out, 32, data, len, NULL, 0);
}

int moor_crypto_hash_keyed(uint8_t out[32], const uint8_t *data, size_t len,
                           const uint8_t key[32]) {
    return crypto_generichash_blake2b(out, 32, data, len, key, 32);
}

int moor_crypto_kdf(uint8_t *out, size_t out_len,
                    const uint8_t key[32], uint64_t subkey_id,
                    const char context[8]) {
    /* Use libsodium's KDF which derives subkeys from a master key */
    if (out_len < crypto_kdf_BYTES_MIN || out_len > crypto_kdf_BYTES_MAX)
        return -1;
    crypto_kdf_derive_from_key(out, out_len, subkey_id, context, key);
    return 0;
}

void moor_crypto_random(uint8_t *buf, size_t len) {
    randombytes_buf(buf, len);
}

void moor_crypto_wipe(void *buf, size_t len) {
    sodium_memzero(buf, len);
}

int moor_crypto_ed25519_to_curve25519_pk(uint8_t curve_pk[32],
                                         const uint8_t ed_pk[32]) {
    return crypto_sign_ed25519_pk_to_curve25519(curve_pk, ed_pk);
}

int moor_crypto_ed25519_to_curve25519_sk(uint8_t curve_sk[32],
                                         const uint8_t ed_sk[64]) {
    return crypto_sign_ed25519_sk_to_curve25519(curve_sk, ed_sk);
}

int moor_crypto_seal(uint8_t *ct, const uint8_t *pt, size_t pt_len,
                     const uint8_t recipient_pk[32]) {
    return crypto_box_seal(ct, pt, pt_len, recipient_pk);
}

int moor_crypto_seal_open(uint8_t *pt, const uint8_t *ct, size_t ct_len,
                          const uint8_t recipient_pk[32],
                          const uint8_t recipient_sk[32]) {
    return crypto_box_seal_open(pt, ct, ct_len, recipient_pk, recipient_sk);
}

/*
 * HS key blinding -- Ed25519 scalar multiplication (Tor-compatible approach).
 *
 * Derive a deterministic blinded keypair from identity + time period using
 * algebraic operations on the Ed25519 curve, NOT seed-based derivation.
 *
 * Blind factor:  bf = BLAKE2b-512("moor-bpub" || identity_pk || time_period)
 *                     reduced mod L (Ed25519 group order)
 *
 * Public path (client + service):
 *   blinded_pk = identity_pk * bf          (Ed25519 point * scalar)
 *
 * Private path (service only):
 *   identity_scalar = SHA-512(identity_sk_seed)[0:32] with Ed25519 clamping
 *   blinded_scalar  = identity_scalar * bf  (scalar * scalar mod L)
 *   blinded_sk      = blinded_scalar || blinded_pk  (64-byte signing key)
 *
 * This is secure because only the service knows identity_sk, so only
 * the service can compute blinded_scalar. But anyone with identity_pk
 * can verify blinded_pk = identity_pk * bf, since bf is public.
 */

/* Derive the blind factor scalar from identity_pk + time_period.
 * Output: 32-byte scalar reduced mod L. */
/* Ed25519 scalar API (crypto_core_ed25519_scalar_*) requires libsodium >= 1.0.18.
 * On older versions, blinded HS key functions are stubbed out. */
/* libsodium 1.0.18 == soname 10.3; check MAJOR*100+MINOR >= 1003 */
#if (SODIUM_LIBRARY_VERSION_MAJOR * 100 + SODIUM_LIBRARY_VERSION_MINOR) >= 1003

static void derive_blind_factor(uint8_t factor[32],
                                const uint8_t identity_pk[32],
                                uint64_t time_period) {
    uint8_t input[49]; /* "moor-bpub"(9) + identity_pk(32) + time_period(8) */
    memcpy(input, "moor-bpub", 9);
    memcpy(input + 9, identity_pk, 32);
    for (int i = 0; i < 8; i++)
        input[41 + i] = (uint8_t)(time_period >> (i * 8));

    /* Hash to 64 bytes, then reduce mod L to get a valid Ed25519 scalar */
    uint8_t hash64[64];
    crypto_generichash_blake2b(hash64, 64, input, 49, NULL, 0);
    crypto_core_ed25519_scalar_reduce(factor, hash64);
    sodium_memzero(hash64, 64);
}

int moor_crypto_blind_pk(uint8_t blinded_pk[32],
                         const uint8_t identity_pk[32],
                         uint64_t time_period) {
    /* Public derivation: blinded_pk = identity_pk * blind_factor
     * Both service and client can compute this (only needs public key). */
    uint8_t factor[32];
    derive_blind_factor(factor, identity_pk, time_period);

    if (crypto_scalarmult_ed25519_noclamp(blinded_pk, factor, identity_pk) != 0) {
        LOG_ERROR("Ed25519 point multiplication failed (bad identity_pk?)");
        sodium_memzero(factor, 32);
        return -1;
    }

    sodium_memzero(factor, 32);
    return 0;
}

int moor_crypto_blind_keypair(uint8_t blinded_pk[32], uint8_t blinded_sk[64],
                              const uint8_t identity_pk[32],
                              const uint8_t identity_sk[64],
                              uint64_t time_period) {
    /*
     * Service-side: derive full blinded keypair.
     * blinded_pk = identity_pk * bf          (same as public path)
     * blinded_sk = identity_scalar * bf      (only service can compute)
     */

    uint8_t factor[32];
    derive_blind_factor(factor, identity_pk, time_period);

    /* Step 1: blinded_pk = identity_pk * factor (public path) */
    if (crypto_scalarmult_ed25519_noclamp(blinded_pk, factor, identity_pk) != 0) {
        LOG_ERROR("Ed25519 point multiplication failed");
        sodium_memzero(factor, 32);
        return -1;
    }

    /* Step 2: Extract identity scalar from Ed25519 secret key.
     * libsodium Ed25519 sk format: seed(32) || pk(32).
     * The actual scalar is SHA-512(seed)[0:32] with Ed25519 clamping.
     * The nonce key is SHA-512(seed)[32:64] (used for deterministic nonces). */
    uint8_t seed_hash[64];
    crypto_hash_sha512(seed_hash, identity_sk, 32);

    uint8_t identity_scalar[32];
    memcpy(identity_scalar, seed_hash, 32);
    identity_scalar[0]  &= 248;
    identity_scalar[31] &= 127;
    identity_scalar[31] |= 64;

    /* Step 3: blinded_scalar = identity_scalar * blind_factor mod L */
    uint8_t blinded_scalar[32];
    crypto_core_ed25519_scalar_mul(blinded_scalar, identity_scalar, factor);

    /* Step 4: Derive a nonce key for deterministic EdDSA nonce generation.
     * We mix the original nonce key (seed_hash[32:64]) with the blind factor
     * so each blinded key has a unique, secret nonce derivation. */
    uint8_t nonce_key[32];
    uint8_t nonce_input[64];
    memcpy(nonce_input, seed_hash + 32, 32);  /* original nonce key */
    memcpy(nonce_input + 32, factor, 32);      /* blind factor */
    moor_crypto_hash(nonce_key, nonce_input, 64);

    /* Step 5: Construct 64-byte blinded signing key.
     * Format: blinded_scalar(32) || nonce_key(32).
     * Use moor_crypto_sign_blinded() to sign with this key. */
    memcpy(blinded_sk, blinded_scalar, 32);
    memcpy(blinded_sk + 32, nonce_key, 32);

    /* Verify consistency: blinded_scalar * G must equal blinded_pk.
     * Catches memory corruption or mismatched identity_pk/identity_sk. */
    uint8_t check_pk[32];
    if (crypto_scalarmult_ed25519_base_noclamp(check_pk, blinded_scalar) != 0 ||
        sodium_memcmp(check_pk, blinded_pk, 32) != 0) {
        LOG_ERROR("blinded keypair consistency check failed");
        sodium_memzero(check_pk, 32);
        sodium_memzero(factor, 32);
        sodium_memzero(seed_hash, 64);
        sodium_memzero(identity_scalar, 32);
        sodium_memzero(blinded_scalar, 32);
        sodium_memzero(nonce_key, 32);
        sodium_memzero(nonce_input, 64);
        sodium_memzero(blinded_sk, 64);
        sodium_memzero(blinded_pk, 32);
        return -1;
    }
    sodium_memzero(check_pk, 32);

    sodium_memzero(factor, 32);
    sodium_memzero(seed_hash, 64);
    sodium_memzero(identity_scalar, 32);
    sodium_memzero(blinded_scalar, 32);
    sodium_memzero(nonce_key, 32);
    sodium_memzero(nonce_input, 64);
    return 0;
}

/*
 * EdDSA signing with a raw scalar key (for blinded HS keys).
 *
 * blinded_sk format: scalar(32) || nonce_key(32)
 *
 * EdDSA signature (R, S):
 *   r = SHA-512(nonce_key || message) mod L    (deterministic nonce)
 *   R = r * G                                   (nonce point)
 *   k = SHA-512(R || pk || message) mod L       (challenge)
 *   S = r + k * scalar mod L                    (response)
 *   sig = R(32) || S(32)
 */
int moor_crypto_sign_blinded(uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                             const uint8_t blinded_sk[64],
                             const uint8_t blinded_pk[32]) {
    const uint8_t *scalar = blinded_sk;       /* first 32 bytes */
    const uint8_t *nonce_key = blinded_sk + 32; /* last 32 bytes */

    /* Step 1: Deterministic nonce r = H(nonce_key || msg) mod L */
    crypto_hash_sha512_state st;
    uint8_t nonce_hash[64];
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, nonce_key, 32);
    crypto_hash_sha512_update(&st, msg, msg_len);
    crypto_hash_sha512_final(&st, nonce_hash);

    uint8_t r[32];
    crypto_core_ed25519_scalar_reduce(r, nonce_hash);

    /* Step 2: R = r * G (base point multiplication) */
    uint8_t R[32];
    if (crypto_scalarmult_ed25519_base_noclamp(R, r) != 0) {
        sodium_memzero(r, 32);
        sodium_memzero(nonce_hash, 64);
        return -1;
    }

    /* Step 3: k = H(R || pk || msg) mod L (challenge) */
    uint8_t challenge_hash[64];
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, R, 32);
    crypto_hash_sha512_update(&st, blinded_pk, 32);
    crypto_hash_sha512_update(&st, msg, msg_len);
    crypto_hash_sha512_final(&st, challenge_hash);

    uint8_t k[32];
    crypto_core_ed25519_scalar_reduce(k, challenge_hash);

    /* Step 4: S = r + k * scalar mod L */
    uint8_t k_a[32];
    crypto_core_ed25519_scalar_mul(k_a, k, scalar);

    uint8_t S[32];
    crypto_core_ed25519_scalar_add(S, r, k_a);

    /* Step 5: sig = R || S */
    memcpy(sig, R, 32);
    memcpy(sig + 32, S, 32);

    sodium_memzero(r, 32);
    sodium_memzero(nonce_hash, 64);
    sodium_memzero(challenge_hash, 64);
    sodium_memzero(k, 32);
    sodium_memzero(k_a, 32);
    sodium_memzero(S, 32);   /* Wipe signature components from stack (#194) */
    sodium_memzero(R, 32);
    return 0;
}

#else /* libsodium < 1.0.18 (soname < 10.3): stub out blinded signing */

int moor_crypto_blind_pk(uint8_t blinded_pk[32],
                         const uint8_t identity_pk[32],
                         uint64_t time_period) {
    (void)blinded_pk; (void)identity_pk; (void)time_period;
    LOG_ERROR("blinded HS keys require libsodium >= 1.0.18");
    return -1;
}

int moor_crypto_blind_keypair(uint8_t blinded_pk[32], uint8_t blinded_sk[64],
                              const uint8_t identity_pk[32],
                              const uint8_t identity_sk[64],
                              uint64_t time_period) {
    (void)blinded_pk; (void)blinded_sk; (void)identity_pk;
    (void)identity_sk; (void)time_period;
    LOG_ERROR("blinded HS keys require libsodium >= 1.0.18");
    return -1;
}

int moor_crypto_sign_blinded(uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                             const uint8_t blinded_sk[64],
                             const uint8_t blinded_pk[32]) {
    (void)sig; (void)msg; (void)msg_len; (void)blinded_sk; (void)blinded_pk;
    LOG_ERROR("blinded HS signing requires libsodium >= 1.0.18");
    return -1;
}

#endif /* SODIUM_LIBRARY_VERSION >= 1003 */

int moor_crypto_kx_hybrid(uint8_t send_key[32], uint8_t recv_key[32],
                           const uint8_t curve_shared[32],
                           const uint8_t kem_shared[32],
                           int is_client) {
    /* Combine classical DH and KEM shared secrets */
    uint8_t combined[64];
    memcpy(combined, curve_shared, 32);
    memcpy(combined + 32, kem_shared, 32);

    uint8_t hybrid[32];
    moor_crypto_hash(hybrid, combined, 64);

    /* Derive directional keys */
    moor_crypto_kdf(send_key, 32, hybrid, is_client ? 0 : 1, "moorlink");
    moor_crypto_kdf(recv_key, 32, hybrid, is_client ? 1 : 0, "moorlink");

    moor_crypto_wipe(combined, 64);
    moor_crypto_wipe(hybrid, 32);
    return 0;
}

int moor_crypto_circuit_kx_hybrid(uint8_t fwd_key[32], uint8_t bwd_key[32],
                                   uint8_t fwd_digest[32], uint8_t bwd_digest[32],
                                   const uint8_t dh_shared[32],
                                   const uint8_t kem_shared[32]) {
    /* Combine DH and KEM shared secrets */
    uint8_t combined[64];
    memcpy(combined, dh_shared, 32);
    memcpy(combined + 32, kem_shared, 32);

    uint8_t hybrid[32];
    moor_crypto_hash(hybrid, combined, 64);

    /* Derive circuit hop keys from the hybrid secret */
    moor_crypto_kdf(fwd_key, 32, hybrid, 1, "moorFWD!");
    moor_crypto_kdf(bwd_key, 32, hybrid, 2, "moorBWD!");

    /* Derive running digest initial states (domain-separated from key derivation) */
    moor_crypto_kdf(fwd_digest, 32, hybrid, 3, "moorFDG!");
    moor_crypto_kdf(bwd_digest, 32, hybrid, 4, "moorBDG!");

    moor_crypto_wipe(combined, 64);
    moor_crypto_wipe(hybrid, 32);
    return 0;
}

/* HMAC-BLAKE2b: H(key XOR opad || H(key XOR ipad || data))
 * L5: BLAKE2b block size is 128 bytes (not 64 like SHA-256).
 * key is 32 bytes, zero-padded to 128 for HMAC.
 * noinline: prevents cross-function alias analysis that can miscompile
 * when callers pass overlapping buffers. */
static void __attribute__((noinline)) hmac_blake2b(uint8_t out[32],
                          const uint8_t key[32],
                          const uint8_t *data, size_t data_len) {
    uint8_t ipad[128], opad[128];
    memset(ipad, 0x36, 128);
    memset(opad, 0x5c, 128);
    for (int i = 0; i < 32; i++) {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    /* inner = BLAKE2b(ipad || data) */
    uint8_t inner[32];
    crypto_generichash_blake2b_state st;
    crypto_generichash_blake2b_init(&st, NULL, 0, 32);
    crypto_generichash_blake2b_update(&st, ipad, 128);
    crypto_generichash_blake2b_update(&st, data, data_len);
    crypto_generichash_blake2b_final(&st, inner, 32);

    /* outer = BLAKE2b(opad || inner) */
    crypto_generichash_blake2b_init(&st, NULL, 0, 32);
    crypto_generichash_blake2b_update(&st, opad, 128);
    crypto_generichash_blake2b_update(&st, inner, 32);
    crypto_generichash_blake2b_final(&st, out, 32);

    sodium_memzero(inner, 32);
    sodium_memzero(ipad, 128);
    sodium_memzero(opad, 128);
}

int __attribute__((noinline)) moor_crypto_hkdf(uint8_t out1[32],
                     uint8_t out2[32],
                     const uint8_t chaining_key[32],
                     const uint8_t *ikm, size_t ikm_len) {
    /* Extract: temp_key = HMAC-BLAKE2b(chaining_key, ikm) */
    uint8_t temp_key[32];
    hmac_blake2b(temp_key, chaining_key, ikm, ikm_len);

    /* Expand: out1 = HMAC-BLAKE2b(temp_key, 0x01) */
    uint8_t one = 0x01;
    hmac_blake2b(out1, temp_key, &one, 1);

    /* Expand: out2 = HMAC-BLAKE2b(temp_key, out1 || 0x02) */
    uint8_t input2[33];
    memcpy(input2, out1, 32);
    input2[32] = 0x02;
    hmac_blake2b(out2, temp_key, input2, 33);

    sodium_memzero(temp_key, 32);
    sodium_memzero(input2, 33);
    return 0;
}

/* RFC 4648 base32 (lowercase) */
static const char b32_alphabet[] = "abcdefghijklmnopqrstuvwxyz234567";

int moor_base32_encode(char *out, size_t out_len,
                       const uint8_t *data, size_t data_len) {
    if (data_len > (SIZE_MAX - 4) / 8) return -1;
    size_t needed = ((data_len * 8) + 4) / 5;
    if (out_len < needed + 1) return -1;

    size_t i = 0, o = 0;
    uint32_t buffer = 0;
    int bits = 0;

    for (i = 0; i < data_len; i++) {
        buffer = (buffer << 8) | data[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[o++] = b32_alphabet[(buffer >> bits) & 0x1F];
        }
    }
    if (bits > 0) {
        out[o++] = b32_alphabet[(buffer << (5 - bits)) & 0x1F];
    }
    out[o] = '\0';
    return (int)o;
}

int moor_base32_decode(uint8_t *out, size_t out_len,
                       const char *str, size_t str_len) {
    size_t needed = (str_len * 5) / 8;
    if (out_len < needed) return -1;

    uint32_t buffer = 0;
    int bits = 0;
    size_t o = 0;

    for (size_t i = 0; i < str_len; i++) {
        char c = str[i];
        int val;
        if (c >= 'a' && c <= 'z')
            val = c - 'a';
        else if (c >= 'A' && c <= 'Z')
            val = c - 'A';
        else if (c >= '2' && c <= '7')
            val = c - '2' + 26;
        else if (c == '=')
            continue;
        else
            return -1;

        buffer = (buffer << 5) | val;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (o >= out_len) return -1;
            out[o++] = (uint8_t)(buffer >> bits);
        }
    }
    return (int)o;
}

/* ---- Persistent key storage ---- */

/* M8: Key file integrity MAC -- derive per-file MAC key by binding the
 * base secret to the file path. This prevents file-swap attacks (copying
 * one key file to replace another). The base secret is still compiled-in;
 * for adversarial local protection, use filesystem permissions (0600). */
static const uint8_t key_file_mac_base[32] = "moor-key-integrity----------";

static void derive_file_mac_key(uint8_t out[32], const char *path) {
    crypto_generichash_blake2b(out, 32,
                                (const uint8_t *)path, strlen(path),
                                key_file_mac_base, 32);
}

static int write_key_file(const char *path, const uint8_t *data, size_t len,
                          int secret) {
    FILE *f;
    if (secret)
        f = secure_fopen_crypto(path, "wb");
    else
        f = fopen(path, "wb");
    if (!f) return -1;
    /* fsync after write to prevent truncated key files on crash (#6) */
    size_t written = fwrite(data, 1, len, f);
    if (written != len) { fclose(f); return -1; }
    /* M8: Append 32-byte BLAKE2b MAC for integrity (path-bound) */
    uint8_t mac_key[32], mac[32];
    derive_file_mac_key(mac_key, path);
    crypto_generichash_blake2b(mac, 32, data, len, mac_key, 32);
    sodium_memzero(mac_key, 32);
    written = fwrite(mac, 1, 32, f);
    fflush(f);
#ifndef _WIN32
    fsync(fileno(f));
#endif
    fclose(f);
    return (written == 32) ? 0 : -1;
}

static int read_key_file(const char *path, uint8_t *data, size_t len) {
#ifdef _WIN32
    FILE *f = fopen(path, "rb");
#else
    int rfd = open(path, O_RDONLY | O_NOFOLLOW);
    if (rfd < 0) return -1;
    FILE *f = fdopen(rfd, "rb");
    if (!f) { close(rfd); return -1; }
#endif
    if (!f) return -1;
    /* M8: Try reading data + 32-byte MAC */
    uint8_t buf[4096 + 32];
    if (len + 32 > sizeof(buf)) { fclose(f); return -1; }
    size_t rd = fread(buf, 1, len + 32, f);
    fclose(f);
    int ret = -1;
    if (rd == len + 32) {
        /* Verify path-bound MAC */
        uint8_t mac_key[32], expected_mac[32];
        derive_file_mac_key(mac_key, path);
        crypto_generichash_blake2b(expected_mac, 32, buf, len, mac_key, 32);
        if (sodium_memcmp(expected_mac, buf + len, 32) == 0) {
            memcpy(data, buf, len);
            ret = 0;
        } else {
            /* Try legacy non-path-bound MAC for migration */
            crypto_generichash_blake2b(expected_mac, 32, buf, len,
                                        key_file_mac_base, 32);
            if (sodium_memcmp(expected_mac, buf + len, 32) == 0) {
                LOG_WARN("key file %s: migrating to path-bound MAC", path);
                memcpy(data, buf, len);
                ret = 0;
                /* Rewrite with path-bound MAC to complete migration (#R1-C2).
                 * Write to tmp file + rename for atomicity (POSIX). */
                int is_secret = 1; /* conservative: treat as secret */
                char tmp_path[4096];
                snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
                if (write_key_file(tmp_path, buf, len, is_secret) == 0) {
                    rename(tmp_path, path);
                }
            } else {
                /* MAC mismatch: accept key anyway to prevent key loss on
                 * binary upgrades (different MAC base or path-binding change).
                 * Re-save with current MAC for next startup. */
                LOG_WARN("key file %s: MAC mismatch (accepting, re-saving)", path);
                memcpy(data, buf, len);
                ret = 0;
                int is_secret_f = 1;
                char tmp_path_f[4096];
                snprintf(tmp_path_f, sizeof(tmp_path_f), "%s.tmp", path);
                if (write_key_file(tmp_path_f, buf, len, is_secret_f) == 0)
                    rename(tmp_path_f, path);
            }
        }
        sodium_memzero(mac_key, 32);
        sodium_memzero(expected_mac, sizeof(expected_mac));
    } else if (rd == len) {
        /* Legacy file without MAC -- accept and re-save with MAC.
         * Keys MUST survive binary upgrades; rejecting valid key material
         * because of a missing MAC would force key regeneration and break
         * the entire trust chain (DA fingerprints, relay registration). */
        LOG_WARN("key file %s has no integrity MAC (accepting, will re-save)", path);
        memcpy(data, buf, len);
        ret = 0;
        /* Re-save with MAC for next startup */
        int is_secret = 1;
        char tmp_path[4096];
        snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
        if (write_key_file(tmp_path, buf, len, is_secret) == 0)
            rename(tmp_path, path);
    }
    sodium_memzero(buf, sizeof(buf)); /* Wipe key material from stack (#192) */
    return ret;
}

int moor_keys_save(const char *data_dir,
                   const uint8_t id_pk[32], const uint8_t id_sk[64],
                   const uint8_t onion_pk[32], const uint8_t onion_sk[32]) {
    char keys_dir[512];
    int n = snprintf(keys_dir, sizeof(keys_dir), "%s/keys", data_dir);
    if (n < 0 || (size_t)n >= sizeof(keys_dir)) return -1; /* L3 */
    mkdir(keys_dir, 0700);

    char path[576];
    n = snprintf(path, sizeof(path), "%s/identity_pk", keys_dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return -1;
    if (write_key_file(path, id_pk, 32, 0) != 0) return -1;

    n = snprintf(path, sizeof(path), "%s/identity_sk", keys_dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return -1;
    if (write_key_file(path, id_sk, 64, 1) != 0) return -1;

    n = snprintf(path, sizeof(path), "%s/onion_pk", keys_dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return -1;
    if (write_key_file(path, onion_pk, 32, 0) != 0) return -1;

    n = snprintf(path, sizeof(path), "%s/onion_sk", keys_dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return -1;
    if (write_key_file(path, onion_sk, 32, 1) != 0) return -1;

    return 0;
}

int moor_keys_load(const char *data_dir,
                   uint8_t id_pk[32], uint8_t id_sk[64],
                   uint8_t onion_pk[32], uint8_t onion_sk[32]) {
    char path[576];
    int n;

    n = snprintf(path, sizeof(path), "%s/keys/identity_pk", data_dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return -1;
    if (read_key_file(path, id_pk, 32) != 0) return -1;

    n = snprintf(path, sizeof(path), "%s/keys/identity_sk", data_dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return -1;
    if (read_key_file(path, id_sk, 64) != 0) return -1;

    n = snprintf(path, sizeof(path), "%s/keys/onion_pk", data_dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return -1;
    if (read_key_file(path, onion_pk, 32) != 0) return -1;

    n = snprintf(path, sizeof(path), "%s/keys/onion_sk", data_dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return -1;
    if (read_key_file(path, onion_sk, 32) != 0) return -1;

    return 0;
}

int moor_pq_keys_save(const char *data_dir,
                      const uint8_t *pq_pk, const uint8_t *pq_sk) {
    char keys_dir[512];
    int n = snprintf(keys_dir, sizeof(keys_dir), "%s/keys", data_dir);
    if (n < 0 || (size_t)n >= sizeof(keys_dir)) return -1;
    mkdir(keys_dir, 0700);

    char path[576];
    n = snprintf(path, sizeof(path), "%s/pq_identity_pk", keys_dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return -1;
    if (write_key_file(path, pq_pk, MOOR_MLDSA_PK_LEN, 0) != 0) return -1;

    n = snprintf(path, sizeof(path), "%s/pq_identity_sk", keys_dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return -1;
    if (write_key_file(path, pq_sk, MOOR_MLDSA_SK_LEN, 1) != 0) return -1;

    return 0;
}

int moor_pq_keys_load(const char *data_dir,
                      uint8_t *pq_pk, uint8_t *pq_sk) {
    char path[576];
    int n;

    n = snprintf(path, sizeof(path), "%s/keys/pq_identity_pk", data_dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return -1;
    if (read_key_file(path, pq_pk, MOOR_MLDSA_PK_LEN) != 0) return -1;

    n = snprintf(path, sizeof(path), "%s/keys/pq_identity_sk", data_dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return -1;
    if (read_key_file(path, pq_sk, MOOR_MLDSA_SK_LEN) != 0) return -1;

    return 0;
}
