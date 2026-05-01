#ifndef MOOR_CRYPTO_H
#define MOOR_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

/* Initialize libsodium. Must be called once at startup. Returns 0 on success. */
int moor_crypto_init(void);

/* Ed25519 keygen */
void moor_crypto_sign_keygen(uint8_t pk[32], uint8_t sk[64]);

/* Ed25519 sign: sig is 64 bytes */
int moor_crypto_sign(uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                     const uint8_t sk[64]);

/* Ed25519 verify */
int moor_crypto_sign_verify(const uint8_t sig[64], const uint8_t *msg,
                            size_t msg_len, const uint8_t pk[32]);

/* Curve25519 keygen for onion keys */
void moor_crypto_box_keygen(uint8_t pk[32], uint8_t sk[32]);

/* Curve25519 DH: shared_out = scalarmult(our_sk, their_pk) */
int moor_crypto_dh(uint8_t shared_out[32], const uint8_t our_sk[32],
                   const uint8_t their_pk[32]);

/* Key exchange: derive send/recv keys from DH */
int moor_crypto_kx_client(uint8_t send_key[32], uint8_t recv_key[32],
                          const uint8_t client_pk[32], const uint8_t client_sk[32],
                          const uint8_t server_pk[32]);

int moor_crypto_kx_server(uint8_t send_key[32], uint8_t recv_key[32],
                          const uint8_t server_pk[32], const uint8_t server_sk[32],
                          const uint8_t client_pk[32]);

/* AEAD encrypt: ChaCha20-Poly1305
 * ct must have room for pt_len + 16 (MAC)
 * Returns 0 on success */
int moor_crypto_aead_encrypt(uint8_t *ct, size_t *ct_len,
                             const uint8_t *pt, size_t pt_len,
                             const uint8_t *ad, size_t ad_len,
                             const uint8_t key[32], uint64_t nonce);

/* AEAD decrypt */
int moor_crypto_aead_decrypt(uint8_t *pt, size_t *pt_len,
                             const uint8_t *ct, size_t ct_len,
                             const uint8_t *ad, size_t ad_len,
                             const uint8_t key[32], uint64_t nonce);

/* AEAD encrypt/decrypt variants taking a full 96-bit (12-byte) nonce.
 * Used by HS descriptors v2 where the birthday bound at 64 bits under a
 * per-time-period key was deemed too tight for comfort. */
int moor_crypto_aead_encrypt_n12(uint8_t *ct, size_t *ct_len,
                                  const uint8_t *pt, size_t pt_len,
                                  const uint8_t *ad, size_t ad_len,
                                  const uint8_t key[32],
                                  const uint8_t nonce[12]);

int moor_crypto_aead_decrypt_n12(uint8_t *pt, size_t *pt_len,
                                  const uint8_t *ct, size_t ct_len,
                                  const uint8_t *ad, size_t ad_len,
                                  const uint8_t key[32],
                                  const uint8_t nonce[12]);

/* BLAKE2b-256 hash */
int moor_crypto_hash(uint8_t out[32], const uint8_t *data, size_t len);

/* BLAKE2b with key (MAC) */
int moor_crypto_hash_keyed(uint8_t out[32], const uint8_t *data, size_t len,
                           const uint8_t key[32]);

/* HKDF-like: derive subkeys from shared secret + context */
int moor_crypto_kdf(uint8_t *out, size_t out_len,
                    const uint8_t key[32], uint64_t subkey_id,
                    const char context[8]);

/* Secure random bytes */
void moor_crypto_random(uint8_t *buf, size_t len);

/* Secure memory wipe */
void moor_crypto_wipe(void *buf, size_t len);

/* Convert Ed25519 pk to Curve25519 pk */
int moor_crypto_ed25519_to_curve25519_pk(uint8_t curve_pk[32],
                                         const uint8_t ed_pk[32]);

/* Convert Ed25519 sk to Curve25519 sk */
int moor_crypto_ed25519_to_curve25519_sk(uint8_t curve_sk[32],
                                         const uint8_t ed_sk[64]);

/* Stream cipher XOR for onion layers (no MAC, fixed-size cells).
 * Encrypts buf in-place. Same call encrypts and decrypts (XOR). */
int moor_crypto_stream_xor(uint8_t *buf, size_t len,
                           const uint8_t key[32], uint64_t nonce);

/* Anonymous sealed box: encrypt to recipient's public key.
 * Ciphertext is pt_len + MOOR_SEAL_OVERHEAD bytes. */
int moor_crypto_seal(uint8_t *ct, const uint8_t *pt, size_t pt_len,
                     const uint8_t recipient_pk[32]);

/* Open sealed box. Returns 0 on success. */
int moor_crypto_seal_open(uint8_t *pt, const uint8_t *ct, size_t ct_len,
                          const uint8_t recipient_pk[32],
                          const uint8_t recipient_sk[32]);

/* Post-quantum anonymous sealing via ML-KEM-768 + ChaCha20-Poly1305.
 * Layout of ct: kem_ct(MOOR_KEM_CT_LEN=1088) || aead_ct(pt_len) || aead_tag(16)
 * Total ciphertext length: MOOR_KEM_CT_LEN + pt_len + MOOR_PQ_SEAL_AEAD_TAG.
 * Anonymous (no client key used); suitable for HS INTRODUCE1 payload. */
#define MOOR_PQ_SEAL_AEAD_TAG 16
#define MOOR_PQ_SEAL_OVERHEAD (MOOR_KEM_CT_LEN + MOOR_PQ_SEAL_AEAD_TAG)
int moor_crypto_pq_seal(uint8_t *ct, const uint8_t *pt, size_t pt_len,
                        const uint8_t *recipient_kem_pk /* MOOR_KEM_PK_LEN */);
int moor_crypto_pq_seal_open(uint8_t *pt, const uint8_t *ct, size_t ct_len,
                             const uint8_t *recipient_kem_sk /* MOOR_KEM_SK_LEN */);

/* HS key blinding: derive time-period-specific keypair using Ed25519
 * scalar multiplication (Tor-compatible approach).
 * Service calls with identity_pk + identity_sk to get blinded_pk + blinded_sk.
 * Client calls moor_crypto_blind_pk with identity_pk only to derive blinded_pk.
 *
 * blinded_sk format: scalar(32) || nonce_key(32) -- NOT a standard Ed25519 sk.
 * Use moor_crypto_sign_blinded() to sign with blinded_sk, NOT moor_crypto_sign(). */
int moor_crypto_blind_keypair(uint8_t blinded_pk[32], uint8_t blinded_sk[64],
                              const uint8_t identity_pk[32],
                              const uint8_t identity_sk[64],
                              uint64_t time_period);

int moor_crypto_blind_pk(uint8_t blinded_pk[32],
                         const uint8_t identity_pk[32],
                         uint64_t time_period);

/* Ed25519 sign using a blinded secret key (raw scalar format).
 * blinded_sk format: scalar(32) || nonce_key(32).
 * Signatures produced are standard Ed25519 and verify with crypto_sign_verify. */
int moor_crypto_sign_blinded(uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                             const uint8_t blinded_sk[64],
                             const uint8_t blinded_pk[32]);

/* PQ symmetric-key derivation (link layer): derive bidir keys from
 * ML-KEM shared secret. Name retained as _hybrid for ABI continuity with
 * pre-PQ callers; internals are KEM-only post Phase 1a. */
int moor_crypto_kx_pq(uint8_t send_key[32], uint8_t recv_key[32],
                       const uint8_t kem_shared[32],
                       int is_client);

/* PQ symmetric-key derivation (circuit layer): derive forward/backward
 * keys + running digests from ML-KEM shared secret. */
int moor_crypto_circuit_kx_pq(uint8_t fwd_key[32], uint8_t bwd_key[32],
                               uint8_t fwd_digest[32], uint8_t bwd_digest[32],
                               const uint8_t kem_shared[32]);

/* HKDF-BLAKE2b for Noise protocol and CKE handshake.
 * Derives two 32-byte keys from chaining_key + input_key_material.
 * Uses HMAC-BLAKE2b extract-then-expand per Noise spec. */
int moor_crypto_hkdf(uint8_t out1[32], uint8_t out2[32],
                     const uint8_t chaining_key[32],
                     const uint8_t *ikm, size_t ikm_len);

/* Link-layer rekey KDF. Derives the next 32-byte AEAD key for a link
 * direction using HKDF-Expand over the per-direction chaining key
 * with info = "moor link rekey" || be64(epoch). Epoch is monotonic
 * and starts at 0 — out_key for epoch 0 is the first post-rotation key
 * (epoch 0 itself uses the Noise-derived key with no rotation). */
int moor_crypto_link_rekey(uint8_t out_key[32],
                           const uint8_t chaining_key[32],
                           uint64_t epoch);

/* Persistent relay key storage */
int moor_keys_save(const char *data_dir,
                   const uint8_t id_pk[32], const uint8_t id_sk[64],
                   const uint8_t onion_pk[32], const uint8_t onion_sk[32]);
int moor_keys_load(const char *data_dir,
                   uint8_t id_pk[32], uint8_t id_sk[64],
                   uint8_t onion_pk[32], uint8_t onion_sk[32]);
/* Public-key-only loader; for --print-fingerprint when the caller does
 * not have read access to identity_sk. */
int moor_identity_pk_load(const char *data_dir, uint8_t id_pk[32]);

/* PQ (ML-DSA-65) key persistence */
int moor_pq_keys_save(const char *data_dir,
                      const uint8_t *pq_pk, const uint8_t *pq_sk);
int moor_pq_keys_load(const char *data_dir,
                      uint8_t *pq_pk, uint8_t *pq_sk);

/* Falcon-512 identity key persistence (Phase 3: post-quantum node ID).
 * pk is MOOR_FALCON_PK_LEN (897), sk is MOOR_FALCON_SK_LEN (1281). */
int moor_falcon_keys_save(const char *data_dir,
                          const uint8_t *falcon_pk, const uint8_t *falcon_sk);
int moor_falcon_keys_load(const char *data_dir,
                          uint8_t *falcon_pk, uint8_t *falcon_sk);

/* Base32 encode/decode for .moor addresses */
int moor_base32_encode(char *out, size_t out_len,
                       const uint8_t *data, size_t data_len);
int moor_base32_decode(uint8_t *out, size_t out_len,
                       const char *str, size_t str_len);

#endif /* MOOR_CRYPTO_H */
