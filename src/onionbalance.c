/*
 * MOOR -- OnionBalance: aggregate intro points from multiple HS backends
 */
#include "moor/moor.h"
#include <sodium.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define close closesocket
#define MSG_NOSIGNAL 0
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

int moor_ob_init(moor_ob_config_t *config) {
    /* Load or generate master keys */
    char path[512];

    snprintf(path, sizeof(path), "%s/identity_sk", config->hs_dir);
    FILE *f = fopen(path, "rb");
    if (f) {
        if (fread(config->identity_sk, 1, 64, f) != 64) { fclose(f); return -1; }
        fclose(f);

        snprintf(path, sizeof(path), "%s/identity_pk", config->hs_dir);
        f = fopen(path, "rb");
        if (!f) return -1;
        if (fread(config->identity_pk, 1, 32, f) != 32) { fclose(f); return -1; }
        fclose(f);

        snprintf(path, sizeof(path), "%s/onion_sk", config->hs_dir);
        f = fopen(path, "rb");
        if (!f) return -1;
        if (fread(config->onion_sk, 1, 32, f) != 32) { fclose(f); return -1; }
        fclose(f);

        snprintf(path, sizeof(path), "%s/onion_pk", config->hs_dir);
        f = fopen(path, "rb");
        if (!f) return -1;
        if (fread(config->onion_pk, 1, 32, f) != 32) { fclose(f); return -1; }
        fclose(f);

        moor_hs_compute_address(config->moor_address,
                                 sizeof(config->moor_address),
                                 config->identity_pk);
        LOG_INFO("OB: loaded master keys");
    } else {
        /* Generate new keys */
        moor_crypto_sign_keygen(config->identity_pk, config->identity_sk);
        moor_crypto_box_keygen(config->onion_pk, config->onion_sk);
        moor_hs_compute_address(config->moor_address,
                                 sizeof(config->moor_address),
                                 config->identity_pk);

        /* Save keys */
        moor_hs_config_t tmp;
        memset(&tmp, 0, sizeof(tmp));
        memcpy(tmp.identity_pk, config->identity_pk, 32);
        memcpy(tmp.identity_sk, config->identity_sk, 64);
        memcpy(tmp.onion_pk, config->onion_pk, 32);
        memcpy(tmp.onion_sk, config->onion_sk, 32);
        snprintf(tmp.hs_dir, sizeof(tmp.hs_dir), "%s", config->hs_dir);
        snprintf(tmp.moor_address, sizeof(tmp.moor_address), "%s",
                 config->moor_address);
        moor_hs_save_keys(&tmp);

        LOG_INFO("OB: generated master keys");
    }

    config->num_backends = 0;

    /* Generate PoW seed if enabled */
    if (config->pow_enabled && config->pow_difficulty > 0)
        moor_crypto_random(config->pow_seed, 32);

    return 0;
}

int moor_ob_handle_backend(moor_ob_config_t *config,
                            const uint8_t *data, size_t len) {
    /*
     * Backend descriptor upload format:
     *   backend_pk(32) + signature(64) + num_intro(1) +
     *   [node_id(32) + address(64) + or_port(2)] * N
     *
     * The signature covers everything after the signature field
     * (num_intro + intro point entries) using the backend's Ed25519 key.
     */
    if (len < 97) return -1; /* 32 + 64 + 1 minimum */

    uint8_t backend_pk[32];
    memcpy(backend_pk, data, 32);
    const uint8_t *signature = data + 32;
    const uint8_t *signed_data = data + 96; /* everything after signature */
    size_t signed_len = len - 96;

    /* Verify Ed25519 signature over the descriptor body */
    if (crypto_sign_ed25519_verify_detached(signature, signed_data,
                                             signed_len, backend_pk) != 0) {
        LOG_WARN("OB: backend descriptor signature verification failed");
        return -1;
    }

    int num_intro = signed_data[0];
    if (num_intro > MOOR_OB_MAX_INTRO_PER_BACKEND) num_intro = MOOR_OB_MAX_INTRO_PER_BACKEND;

    size_t expected = 97 + (size_t)num_intro * 98;
    if (len < expected) return -1;

    /* Find or allocate backend slot */
    int slot = -1;
    for (int i = 0; i < config->num_backends; i++) {
        if (sodium_memcmp(config->backends[i].backend_pk, backend_pk, 32) == 0) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        if (config->num_backends >= MOOR_OB_MAX_BACKENDS) {
            LOG_WARN("OB: max backends reached, rejecting");
            return -1;
        }
        slot = config->num_backends++;
        memcpy(config->backends[slot].backend_pk, backend_pk, 32);
    }

    /* Update intro points */
    config->backends[slot].num_intro = num_intro;
    size_t off = 97;
    for (int i = 0; i < num_intro; i++) {
        memcpy(config->backends[slot].intro_points[i].node_id, data + off, 32);
        off += 32;
        memcpy(config->backends[slot].intro_points[i].address, data + off, 64);
        config->backends[slot].intro_points[i].address[63] = '\0';
        off += 64;
        config->backends[slot].intro_points[i].or_port =
            ((uint16_t)data[off] << 8) | data[off + 1];
        off += 2;
    }
    config->backends[slot].last_seen = (uint64_t)time(NULL);

    LOG_INFO("OB: backend %d updated (%d intro points)", slot, num_intro);
    return 0;
}

int moor_ob_live_backend_count(const moor_ob_config_t *config) {
    uint64_t now = (uint64_t)time(NULL);
    int count = 0;
    for (int i = 0; i < config->num_backends; i++) {
        if (config->backends[i].num_intro > 0 &&
            (now - config->backends[i].last_seen) < MOOR_OB_STALE_SECS) {
            count++;
        }
    }
    return count;
}

int moor_ob_aggregate_intros(const moor_ob_config_t *config,
                              moor_ob_intro_t *out,
                              int max_out) {
    uint64_t now = (uint64_t)time(NULL);
    int written = 0;

    /* Round-robin across live backends */
    int intro_idx = 0;
    for (int round = 0; round < MOOR_OB_MAX_INTRO_PER_BACKEND && written < max_out; round++) {
        for (int b = 0; b < config->num_backends && written < max_out; b++) {
            if (config->backends[b].num_intro <= intro_idx) continue;
            if ((now - config->backends[b].last_seen) >= MOOR_OB_STALE_SECS) continue;

            memcpy(out[written].node_id,
                   config->backends[b].intro_points[intro_idx].node_id, 32);
            snprintf(out[written].address, 64, "%s",
                     config->backends[b].intro_points[intro_idx].address);
            out[written].or_port =
                config->backends[b].intro_points[intro_idx].or_port;
            written++;
        }
        intro_idx++;
    }

    return written;
}

int moor_ob_publish(moor_ob_config_t *config) {
    int live = moor_ob_live_backend_count(config);
    if (live == 0) {
        LOG_WARN("OB: no live backends, skipping publish");
        return -1;
    }

    /* Aggregate intro points (up to 3) */
    moor_ob_intro_t agg[3];
    int num_agg = moor_ob_aggregate_intros(config, agg, 3);
    if (num_agg == 0) return -1;

    /* Build descriptor signed with master identity */
    moor_hs_descriptor_t desc;
    memset(&desc, 0, sizeof(desc));

    moor_crypto_hash(desc.address_hash, config->identity_pk, 32);
    memcpy(desc.service_pk, config->identity_pk, 32);
    memcpy(desc.onion_pk, config->onion_pk, 32);
    /* Blinded pk: derive for current time period */
    uint64_t time_period = (uint64_t)time(NULL) / MOOR_TIME_PERIOD_SECS;
    uint8_t blinded_pk[32], blinded_sk[64];
    moor_crypto_blind_keypair(blinded_pk, blinded_sk,
                               config->identity_pk, config->identity_sk,
                               time_period);
    memcpy(desc.blinded_pk, blinded_pk, 32);
    sodium_memzero(blinded_sk, sizeof(blinded_sk));

    desc.num_intro_points = (uint32_t)num_agg;
    for (int i = 0; i < num_agg; i++) {
        memcpy(desc.intro_points[i].node_id, agg[i].node_id, 32);
        snprintf(desc.intro_points[i].address, 64, "%s", agg[i].address);
        desc.intro_points[i].or_port = agg[i].or_port;
    }

    /* PoW fields */
    if (config->pow_enabled && config->pow_difficulty > 0) {
        memcpy(desc.pow_seed, config->pow_seed, 32);
        desc.pow_difficulty = (uint8_t)config->pow_difficulty;
    }

    /* Sign descriptor */
    uint8_t to_sign[96];
    memcpy(to_sign, desc.address_hash, 32);
    memcpy(to_sign + 32, desc.service_pk, 32);
    memcpy(to_sign + 64, desc.onion_pk, 32);
    if (moor_crypto_sign(desc.signature, to_sign, 96, config->identity_sk) != 0) {
        LOG_ERROR("OB: descriptor signing failed");
        return -1;
    }
    desc.published = (uint64_t)time(NULL);

    /* Serialize and encrypt */
    uint8_t plaintext[1024];
    int pt_len = moor_hs_descriptor_serialize(plaintext, sizeof(plaintext), &desc);
    if (pt_len < 0) return -1;

    /* Derive encryption key */
    uint8_t desc_key_input[49];
    memcpy(desc_key_input, "moor-desc", 9);
    memcpy(desc_key_input + 9, config->identity_pk, 32);
    for (int i = 0; i < 8; i++)
        desc_key_input[41 + i] = (uint8_t)(time_period >> (i * 8));
    uint8_t desc_key[32];
    moor_crypto_hash(desc_key, desc_key_input, 49);

    uint64_t nonce;
    moor_crypto_random((uint8_t *)&nonce, 8);

    uint8_t ciphertext[1024];
    size_t ct_len;
    if (moor_crypto_aead_encrypt(ciphertext, &ct_len,
                                  plaintext, pt_len,
                                  desc.address_hash, 32,
                                  desc_key, nonce) != 0) {
        moor_crypto_wipe(desc_key, 32);
        return -1;
    }
    moor_crypto_wipe(desc_key, 32);

    /* Build wire data: address_hash(32) + nonce(8) + ciphertext */
    uint8_t wire[1024];
    size_t wire_len = 0;
    memcpy(wire, desc.address_hash, 32); wire_len += 32;
    for (int i = 7; i >= 0; i--) wire[wire_len++] = (uint8_t)(nonce >> (i * 8));
    memcpy(wire + wire_len, ciphertext, ct_len); wire_len += ct_len;

    /* Publish to DA */
    int fd = moor_tcp_connect_simple(config->da_address, config->da_port);
    if (fd < 0) return -1;

    moor_set_socket_timeout(fd, MOOR_DA_REQUEST_TIMEOUT);
    send(fd, "HS_PUBLISH\n", 11, MSG_NOSIGNAL);
    uint8_t len_buf[4];
    len_buf[0] = (uint8_t)(wire_len >> 24);
    len_buf[1] = (uint8_t)(wire_len >> 16);
    len_buf[2] = (uint8_t)(wire_len >> 8);
    len_buf[3] = (uint8_t)(wire_len);
    send(fd, (char *)len_buf, 4, MSG_NOSIGNAL);
    send(fd, (char *)wire, wire_len, MSG_NOSIGNAL);

    char resp[16];
    recv(fd, resp, sizeof(resp), 0);
    close(fd);

    LOG_INFO("OB: published aggregated descriptor (%d backends, %d intros)",
             live, num_agg);
    return 0;
}
