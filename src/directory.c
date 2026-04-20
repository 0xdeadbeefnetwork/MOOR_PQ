#include "moor/moor.h"
#include "moor/transport.h"
#include "moor/geoip.h"
#include "moor/bw_auth.h"
#include "exit_notice.h"
#include <sodium.h>
#include <string.h>
#ifndef _WIN32
#include <fcntl.h>
#endif

/* Trusted DA public keys for consensus signature verification. */
static uint8_t g_trusted_da_pks[16 * 32];
static int g_num_trusted_da_pks = 0;

void moor_set_trusted_da_keys(const moor_da_entry_t *da_list, int num_das) {
    g_num_trusted_da_pks = 0;
    for (int i = 0; i < num_das && i < 16; i++) {
        int has_pk = 0;
        for (int j = 0; j < 32; j++) {
            if (da_list[i].identity_pk[j] != 0) { has_pk = 1; break; }
        }
        if (has_pk) {
            memcpy(g_trusted_da_pks + g_num_trusted_da_pks * 32,
                   da_list[i].identity_pk, 32);
            g_num_trusted_da_pks++;
        }
    }
}
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>

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

/* GeoIP database pointer -- set by moor_da_set_geoip() */
static moor_geoip_db_t *g_da_geoip = NULL;

void moor_da_set_geoip(moor_geoip_db_t *db) { g_da_geoip = db; }

/* Consensus lock helpers -- all mutations to consensus data go through these */
static void da_lock(moor_da_config_t *config) {
    pthread_mutex_lock(&config->consensus_lock);
}
static void da_unlock(moor_da_config_t *config) {
    pthread_mutex_unlock(&config->consensus_lock);
}

/* Forward declarations for async thread helpers */
static void moor_da_propagate_descriptor(moor_da_config_t *config,
                                          const uint8_t *desc_buf,
                                          uint32_t desc_len);
void moor_da_update_published_snapshot(moor_da_config_t *config);

/* Async propagation context for PUBLISH handler — runs descriptor
 * propagation + vote exchange in a thread so the event loop stays
 * responsive for new connections. */
typedef struct {
    moor_da_config_t *config;
    uint8_t *desc_buf;
    uint32_t desc_len;
} da_propagate_ctx_t;

static void *da_propagate_thread(void *arg) {
    da_propagate_ctx_t *ctx = arg;
    if (ctx->config->num_peers > 0)
        moor_da_propagate_descriptor(ctx->config, ctx->desc_buf, ctx->desc_len);
    moor_da_exchange_votes(ctx->config);
    moor_da_update_published_snapshot(ctx->config);
    free(ctx->desc_buf);
    free(ctx);
    return NULL;
}

/* Forward declarations for _unlocked helpers (defined below, called from
 * moor_da_handle_request which sits between their declaration sites). */
static int da_add_relay_unlocked(moor_da_config_t *config,
                                 const moor_node_descriptor_t *desc);
static int da_build_consensus_unlocked(moor_da_config_t *config);
static int da_exchange_votes_unlocked(moor_da_config_t *config);
static void da_update_published_snapshot_unlocked(moor_da_config_t *config);

/*
 * Encrypted DA-to-DA channel.
 *
 * DA peers know each other's Ed25519 identity keys. To establish an encrypted
 * link, the initiator does an ephemeral-static Curve25519 DH + HKDF:
 *
 *   Initiator → Responder:  "DA_LINK\n" + initiator_identity_pk(32) + ephemeral_pk(32)
 *   Responder:              looks up initiator's identity_pk in peer list
 *                           derives shared = DH(ephemeral_pk, responder_curve_sk)
 *                           sends back: responder_identity_pk(32) + OK(2)
 *   Both:                   session_key = HKDF(shared, "moor-da\0")
 *
 * After setup, all messages are:  nonce(8) + AEAD(payload) where AEAD adds 16-byte MAC.
 */
typedef struct {
    uint8_t send_key[32];
    uint8_t recv_key[32];
    uint64_t send_nonce;
    uint64_t recv_nonce;
    int fd;
} da_encrypted_channel_t;

/* Reliable send: handle partial writes and EINTR (#206) */
static int da_send_all(int fd, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, (const char *)buf + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

/* Send an encrypted message over DA channel */
static int da_channel_send(da_encrypted_channel_t *ch,
                           const uint8_t *data, size_t data_len) {
    size_t ct_len = data_len + 16; /* AEAD MAC */
    uint8_t *buf = malloc(8 + ct_len);
    if (!buf) return -1;

    /* 8-byte nonce prefix */
    uint64_t n = ch->send_nonce++;
    for (int i = 7; i >= 0; i--) buf[i] = (uint8_t)(n >> ((7 - i) * 8));

    size_t actual_ct_len;
    if (moor_crypto_aead_encrypt(buf + 8, &actual_ct_len,
                                  data, data_len, NULL, 0,
                                  ch->send_key, n) != 0) {
        free(buf);
        return -1;
    }

    /* Length-prefix the whole frame: len(4) + nonce(8) + ciphertext */
    uint32_t frame_len = (uint32_t)(8 + actual_ct_len);
    uint8_t len_buf[4];
    len_buf[0] = (uint8_t)(frame_len >> 24);
    len_buf[1] = (uint8_t)(frame_len >> 16);
    len_buf[2] = (uint8_t)(frame_len >> 8);
    len_buf[3] = (uint8_t)(frame_len);
    if (da_send_all(ch->fd, len_buf, 4) != 0) { free(buf); return -1; }
    int rc = da_send_all(ch->fd, buf, frame_len);
    free(buf);
    return rc;
}

/* Receive an encrypted message. Caller must free *out. Returns plaintext length or -1. */
static ssize_t da_channel_recv(da_encrypted_channel_t *ch,
                                uint8_t **out) {
    /* Read 4-byte length */
    uint8_t len_buf[4];
    size_t got = 0;
    while (got < 4) {
        ssize_t n = recv(ch->fd, (char *)len_buf + got, 4 - got, 0);
        if (n <= 0) return -1;
        got += n;
    }
    uint32_t frame_len = ((uint32_t)len_buf[0] << 24) | ((uint32_t)len_buf[1] << 16) |
                         ((uint32_t)len_buf[2] << 8) | len_buf[3];
    /* Max frame: 2 MB (sufficient for SYNC_RELAYS with MOOR_MAX_RELAYS).
     * Previous 4 MB limit was excessive for DA-to-DA traffic (#CWE-400). */
    if (frame_len < 8 + 16 || frame_len > 2097152) return -1;

    uint8_t *frame = malloc(frame_len);
    if (!frame) return -1;
    got = 0;
    while (got < frame_len) {
        ssize_t n = recv(ch->fd, (char *)frame + got, frame_len - got, 0);
        if (n <= 0) { free(frame); return -1; }
        got += n;
    }

    /* Extract nonce */
    uint64_t n64 = 0;
    for (int i = 0; i < 8; i++) n64 = (n64 << 8) | frame[i];

    /* Verify strict sequential nonce — no gaps, no replay (#205) */
    if (n64 != ch->recv_nonce) { free(frame); return -1; }
    ch->recv_nonce = n64 + 1;

    size_t ct_len = frame_len - 8;
    size_t pt_len;
    uint8_t *pt = malloc(ct_len); /* pt_len <= ct_len - 16 */
    if (!pt) { free(frame); return -1; }

    if (moor_crypto_aead_decrypt(pt, &pt_len,
                                  frame + 8, ct_len, NULL, 0,
                                  ch->recv_key, n64) != 0) {
        free(pt);
        free(frame);
        return -1;
    }
    free(frame);
    *out = pt;
    return (ssize_t)pt_len;
}

/* Initiate encrypted channel to a peer DA using Noise_IK + PQ Kyber.
 * Sends "DA_LINK\n" prefix, then performs the same Noise_IK + Kyber768
 * handshake relays use.  Full forward secrecy, mutual authentication,
 * and post-quantum key exchange — replaces the prior hand-rolled DH. */
static int da_channel_open(da_encrypted_channel_t *ch,
                           const char *peer_addr, uint16_t peer_port,
                           const uint8_t our_identity_pk[32],
                           const uint8_t our_identity_sk[64],
                           const uint8_t peer_identity_pk[32]) {
    memset(ch, 0, sizeof(*ch));
    ch->fd = moor_tcp_connect_simple(peer_addr, peer_port);
    if (ch->fd < 0) return -1;

    /* Send command prefix so the DA server dispatches to the
     * DA_LINK handler before the Noise handshake begins. */
    if (send(ch->fd, "DA_LINK\n", 8, MSG_NOSIGNAL) != 8) {
        close(ch->fd); ch->fd = -1;
        return -1;
    }

    /* Set up a temporary connection for the Noise_IK + PQ handshake.
     * Stack-allocated — NOT in the connection pool. */
    moor_connection_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.fd = ch->fd;
    conn.state = CONN_STATE_HANDSHAKING;

    /* Noise_IK pre-message requires the responder's static key.
     * link_handshake_client converts Ed25519 → Curve25519 internally. */
    memcpy(conn.peer_identity, peer_identity_pk, 32);

    moor_set_socket_timeout(ch->fd, 10);

    if (link_handshake_client_pq(&conn, our_identity_pk, our_identity_sk) != 0) {
        LOG_WARN("DA channel: Noise_IK+PQ handshake failed to %s:%u",
                 peer_addr, peer_port);
        close(ch->fd); ch->fd = -1;
        moor_crypto_wipe(&conn, sizeof(conn));
        return -1;
    }

    /* Copy post-PQ session keys and nonces into the DA channel struct.
     * The data framing (length-prefix + nonce + AEAD) stays unchanged. */
    memcpy(ch->send_key, conn.send_key, 32);
    memcpy(ch->recv_key, conn.recv_key, 32);
    ch->send_nonce = conn.send_nonce;
    ch->recv_nonce = conn.recv_nonce;

    /* Wipe handshake secrets from the temporary connection */
    moor_crypto_wipe(conn.send_key, 32);
    moor_crypto_wipe(conn.recv_key, 32);
    moor_crypto_wipe(conn.our_kx_sk, 32);
    moor_crypto_wipe(conn.our_kx_pk, 32);
    if (conn.hs_state) {
        moor_crypto_wipe(conn.hs_state, sizeof(moor_hs_state_t));
        free(conn.hs_state);
    }

    /* Restore DA-friendly timeouts */
    moor_setsockopt_timeo(ch->fd, SO_SNDTIMEO, 5);
    moor_setsockopt_timeo(ch->fd, SO_RCVTIMEO, 5);

    return 0;
}

/* Accept encrypted channel from a peer DA using Noise_IK + PQ Kyber.
 * Called when we receive "DA_LINK\n" command.  extra_data/extra_len carry
 * any bytes the server's initial recv consumed beyond "DA_LINK\n" (TCP
 * coalescing can pull Noise_IK msg1 bytes into the cmd_buf read).
 * Returns 0 on success with channel ready and peer_pk_out set. */
static int da_channel_accept(da_encrypted_channel_t *ch, int client_fd,
                              const uint8_t our_identity_pk[32],
                              const uint8_t our_identity_sk[64],
                              const moor_da_config_t *config,
                              uint8_t peer_pk_out[32],
                              const uint8_t *extra_data, size_t extra_len) {
    memset(ch, 0, sizeof(*ch));
    ch->fd = client_fd;

    /* Set up a temporary connection for the Noise_IK + PQ handshake.
     * Stack-allocated — NOT in the connection pool. */
    moor_connection_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.fd = client_fd;
    conn.state = CONN_STATE_HANDSHAKING;

    /* Pre-buffer any bytes the cmd_buf recv consumed past "DA_LINK\n".
     * link_handshake_server uses conn_recv_buffered which drains
     * conn.recv_buf before hitting the socket. */
    if (extra_data && extra_len > 0) {
        if (extra_len > sizeof(conn.recv_buf)) extra_len = sizeof(conn.recv_buf);
        memcpy(conn.recv_buf, extra_data, extra_len);
        conn.recv_len = extra_len;
    }

    moor_set_socket_timeout(client_fd, 10);

    if (link_handshake_server_pq(&conn, our_identity_pk, our_identity_sk) != 0) {
        LOG_WARN("DA: Noise_IK+PQ handshake failed (accept)");
        moor_crypto_wipe(&conn, sizeof(conn));
        return -1;
    }

    /* Verify the authenticated initiator is a trusted DA peer.
     * conn.peer_identity holds the initiator's Curve25519 static pk
     * (set by Noise_IK decryption of msg1). Convert each trusted peer's
     * Ed25519 pk to Curve25519 for comparison. */
    int trusted = 0;
    uint8_t our_curve_pk[32];
    moor_crypto_ed25519_to_curve25519_pk(our_curve_pk, our_identity_pk);
    if (sodium_memcmp(our_curve_pk, conn.peer_identity, 32) == 0) {
        LOG_WARN("DA channel: reject self-connect");
        moor_crypto_wipe(&conn, sizeof(conn));
        return -1; /* reject self */
    }
    for (int p = 0; p < config->num_peers; p++) {
        uint8_t peer_curve_pk[32];
        if (moor_crypto_ed25519_to_curve25519_pk(peer_curve_pk,
                config->peers[p].identity_pk) != 0)
            continue;
        if (sodium_memcmp(peer_curve_pk, conn.peer_identity, 32) == 0) {
            trusted = 1;
            memcpy(peer_pk_out, config->peers[p].identity_pk, 32);
            break;
        }
    }
    if (!trusted) {
        LOG_WARN("DA channel: reject unknown initiator (Noise_IK authenticated "
                 "but not in peer list)");
        moor_crypto_wipe(&conn, sizeof(conn));
        return -1;
    }

    /* Copy post-PQ session keys and nonces into the DA channel struct */
    memcpy(ch->send_key, conn.send_key, 32);
    memcpy(ch->recv_key, conn.recv_key, 32);
    ch->send_nonce = conn.send_nonce;
    ch->recv_nonce = conn.recv_nonce;

    /* Wipe handshake secrets */
    moor_crypto_wipe(conn.send_key, 32);
    moor_crypto_wipe(conn.recv_key, 32);
    moor_crypto_wipe(conn.our_kx_sk, 32);
    moor_crypto_wipe(conn.our_kx_pk, 32);
    if (conn.hs_state) {
        moor_crypto_wipe(conn.hs_state, sizeof(moor_hs_state_t));
        free(conn.hs_state);
    }

    /* Restore DA-friendly timeouts */
    moor_setsockopt_timeo(client_fd, SO_RCVTIMEO, 5);
    moor_setsockopt_timeo(client_fd, SO_SNDTIMEO, 5);

    return 0;
}

static void da_channel_close(da_encrypted_channel_t *ch) {
    if (ch->fd >= 0) close(ch->fd);
    moor_crypto_wipe(ch->send_key, 32);
    moor_crypto_wipe(ch->recv_key, 32);
    ch->fd = -1;
}

int moor_da_init(moor_da_config_t *config) {
    moor_consensus_init(&config->consensus, 256);
    config->num_hs_entries = 0;
    pthread_mutex_init(&config->consensus_lock, NULL);
    /* Restore HS descriptors from disk (encrypted blobs, DA can't read them) */
    moor_da_load_hs(config);
    LOG_INFO("directory authority initialized");
    return 0;
}

/* Reject private/reserved addresses in relay descriptors */
static int da_is_private_address(const char *addr) {
    struct in_addr in;
    if (inet_pton(AF_INET, addr, &in) == 1) {
        uint32_t ip = ntohl(in.s_addr);
        if ((ip >> 24) == 127) return 1;  /* loopback */
        if ((ip >> 24) == 10) return 1;   /* RFC 1918 */
        if ((ip >> 20) == (172 << 4 | 1)) return 1;
        if ((ip >> 16) == (192 << 8 | 168)) return 1;
        if ((ip >> 16) == (169 << 8 | 254)) return 1;
        if ((ip >> 24) == 0) return 1;    /* "this" network */
    }
    return 0;
}

/* Internal lockless version -- caller must hold consensus_lock */
static int da_add_relay_unlocked(moor_da_config_t *config,
                                 const moor_node_descriptor_t *desc) {
    /* Verify signature */
    if (moor_node_verify_descriptor(desc) != 0) {
        LOG_WARN("DA: rejecting descriptor with bad signature");
        return -1;
    }

    /* Reject old protocol versions that would desync wire framing.
     * NODE_FEATURES_REQUIRED is set in moor.h -- currently requires
     * CELL_KEM (v0.8+) for cell-based KEM ciphertext transport. */
    if ((desc->features & NODE_FEATURES_REQUIRED) != NODE_FEATURES_REQUIRED) {
        LOG_WARN("DA: rejecting descriptor from %s -- missing required features "
                 "(has 0x%x, need 0x%x)", desc->address,
                 desc->features, NODE_FEATURES_REQUIRED);
        return -1;
    }

    /* Reject old protocol versions that would desync descriptor signatures
     * during DA-to-DA sync.  Relays must upgrade to join the network. */
    if (desc->protocol_version < MOOR_MIN_PROTOCOL_VERSION) {
        LOG_WARN("DA: rejecting descriptor from %s -- protocol version %u "
                 "(minimum %u)", desc->address,
                 desc->protocol_version, MOOR_MIN_PROTOCOL_VERSION);
        return -1;
    }

    /* Strict fleet-equality gate: reject relays built from a different commit.
     * Prevents mixed-binary fleets from causing wire/handshake incompatibilities.
     * Compared as a 16-byte buffer (strncmp would stop at any embedded NUL). */
    if (memcmp(desc->build_id, moor_build_id, MOOR_BUILD_ID_LEN) != 0) {
        char their[17], ours[17];
        memcpy(their, desc->build_id, 16); their[16] = '\0';
        memcpy(ours, moor_build_id, 16);   ours[16]  = '\0';
        LOG_WARN("DA: rejecting descriptor from %s -- build_id '%s' != ours '%s'",
                 desc->address, their, ours);
        return -1;
    }

    /* Reject relays advertising private/reserved addresses */
    if (da_is_private_address(desc->address)) {
        LOG_WARN("DA: rejecting descriptor with private address %s", desc->address);
        return -1;
    }

    /* Reject banned relays: check $data_dir/banned_relays file.
     * Format: one entry per line — nickname or hex identity prefix.
     * Example: "darkhorse" or "3672a0cf" */
    {
        extern moor_config_t g_config;
        if (g_config.data_dir[0]) {
            char ban_path[512];
            snprintf(ban_path, sizeof(ban_path), "%s/banned_relays", g_config.data_dir);
            FILE *bf = fopen(ban_path, "r");
            if (bf) {
                char line[128];
                while (fgets(line, sizeof(line), bf)) {
                    /* Strip newline */
                    size_t ll = strlen(line);
                    while (ll > 0 && (line[ll-1] == '\n' || line[ll-1] == '\r'))
                        line[--ll] = '\0';
                    if (ll == 0 || line[0] == '#') continue;

                    /* Match by nickname (case-insensitive) */
                    if (strcasecmp(line, desc->nickname) == 0) {
                        LOG_WARN("DA: rejecting banned relay '%s' (%s:%u)",
                                 desc->nickname, desc->address, desc->or_port);
                        fclose(bf);
                        return -1;
                    }
                    /* Match by IP address or address prefix */
                    if (strncmp(line, desc->address, ll) == 0) {
                        LOG_WARN("DA: rejecting banned relay at %s (%s)",
                                 desc->address, desc->nickname);
                        fclose(bf);
                        return -1;
                    }
                    /* Match by hex identity prefix */
                    if (ll >= 8) {
                        char id_hex[65];
                        for (int b = 0; b < 32; b++)
                            sprintf(id_hex + b*2, "%02x", desc->identity_pk[b]);
                        if (strncasecmp(line, id_hex, ll) == 0) {
                            LOG_WARN("DA: rejecting banned relay '%s' (id match)",
                                     desc->nickname);
                            fclose(bf);
                            return -1;
                        }
                    }
                }
                fclose(bf);
            }
        }
    }

    /* Check if we already have this relay (update if so) */
    for (uint32_t i = 0; i < config->consensus.num_relays; i++) {
        if (sodium_memcmp(config->consensus.relays[i].identity_pk,
                         desc->identity_pk, 32) == 0) {
            uint64_t saved_first_seen = config->consensus.relays[i].first_seen;
            uint8_t saved_probe_failures = config->consensus.relays[i].probe_failures;
            uint64_t saved_vbw = config->consensus.relays[i].verified_bandwidth;
            memcpy(&config->consensus.relays[i], desc, sizeof(*desc));
            config->consensus.relays[i].first_seen = saved_first_seen;
            config->consensus.relays[i].probe_failures = saved_probe_failures;
            config->consensus.relays[i].verified_bandwidth = saved_vbw;
            /* Track when relay last registered (DA-local, for stale reaper).
             * Do NOT overwrite desc->published — it's part of the relay's
             * Ed25519 signature and must be preserved for DA-to-DA sync. */
            config->consensus.relays[i].last_registered = (uint64_t)time(NULL);
            if (g_da_geoip) {
                const moor_geoip_entry_t *ge = moor_geoip_lookup(g_da_geoip, desc->address);
                if (ge) {
                    config->consensus.relays[i].country_code = ge->country_code;
                    config->consensus.relays[i].as_number = ge->as_number;
                } else if (desc->address6[0]) {
                    /* Fallback: try IPv6 address for country */
                    uint16_t cc6 = moor_geoip_country_for_addr(g_da_geoip, desc->address6);
                    if (cc6) config->consensus.relays[i].country_code = cc6;
                }
            }
            LOG_INFO("DA: updated relay descriptor");
            return 0;
        }
        /* Replace stale entry at same address:port (relay restarted with new keys) */
        if (strcmp(config->consensus.relays[i].address, desc->address) == 0 &&
            config->consensus.relays[i].or_port == desc->or_port) {
            memcpy(&config->consensus.relays[i], desc, sizeof(*desc));
            config->consensus.relays[i].first_seen = (uint64_t)time(NULL);
            config->consensus.relays[i].last_registered = (uint64_t)time(NULL);
            LOG_INFO("DA: replaced stale relay at %s:%u (new identity key)",
                     desc->address, desc->or_port);
            return 0;
        }
    }

    /* Add new relay -- grow array if needed */
    if (config->consensus.num_relays >= MOOR_MAX_RELAYS) {
        LOG_ERROR("DA: relay table full (max %d)", MOOR_MAX_RELAYS);
        return -1;
    }
    if (config->consensus.num_relays >= config->consensus.relay_capacity) {
        uint32_t new_cap = config->consensus.relay_capacity * 2;
        if (new_cap > MOOR_MAX_RELAYS) new_cap = MOOR_MAX_RELAYS;
        if (new_cap < 256) new_cap = 256;
        moor_node_descriptor_t *grown = realloc(config->consensus.relays,
            new_cap * sizeof(moor_node_descriptor_t));
        if (!grown) { LOG_ERROR("DA: realloc failed"); return -1; }
        /* Zero newly allocated entries */
        memset(grown + config->consensus.relay_capacity, 0,
               (new_cap - config->consensus.relay_capacity) * sizeof(moor_node_descriptor_t));
        config->consensus.relays = grown;
        config->consensus.relay_capacity = new_cap;
    }

    uint32_t idx = config->consensus.num_relays++;
    memcpy(&config->consensus.relays[idx], desc, sizeof(*desc));
    config->consensus.relays[idx].first_seen = (uint64_t)time(NULL);
    config->consensus.relays[idx].last_registered = (uint64_t)time(NULL);

    /* GeoIP lookup for new relay: try IPv4 first, fall back to IPv6 */
    if (g_da_geoip) {
        const moor_geoip_entry_t *ge = moor_geoip_lookup(g_da_geoip, desc->address);
        if (ge) {
            config->consensus.relays[idx].country_code = ge->country_code;
            config->consensus.relays[idx].as_number = ge->as_number;
        } else if (desc->address6[0]) {
            uint16_t cc6 = moor_geoip_country_for_addr(g_da_geoip, desc->address6);
            if (cc6) config->consensus.relays[idx].country_code = cc6;
        }
    }
    LOG_INFO("DA: added relay #%u", idx);
    return 0;
}

/* Public API: acquires consensus_lock */
int moor_da_add_relay(moor_da_config_t *config,
                      const moor_node_descriptor_t *desc) {
    da_lock(config);
    int ret = da_add_relay_unlocked(config, desc);
    da_unlock(config);
    return ret;
}

/* Trusted import: skip descriptor signature verification.
 * Used for bootstrap from peer DA's text consensus, which is lossy
 * (doesn't preserve all signed fields like features, prev_onion_pk).
 * Relays re-register with fresh PUBLISH descriptors within 30 minutes. */
int moor_da_add_relay_trusted(moor_da_config_t *config,
                              const moor_node_descriptor_t *desc) {
    da_lock(config);
    /* Skip signature verification — caller trusts the source.
     * Still enforce feature requirements and duplicate detection
     * (handled by da_add_relay_core, which is the part of
     * da_add_relay_unlocked after the sig check). */
    int ret = -1;

    /* Feature check (same as da_add_relay_unlocked).
     * We deliberately skip build_id equality here: text consensus is lossy
     * and doesn't preserve build_id.  Relays re-register within 30 min with
     * fresh PUBLISH descriptors that hit the full da_add_relay_unlocked path,
     * which enforces strict build_id equality. */
    if ((desc->features & NODE_FEATURES_REQUIRED) != NODE_FEATURES_REQUIRED) {
        da_unlock(config);
        return -1;
    }

    /* Duplicate/update check + insertion (same logic as da_add_relay_unlocked) */
    for (uint32_t i = 0; i < config->consensus.num_relays; i++) {
        if (sodium_memcmp(config->consensus.relays[i].identity_pk,
                         desc->identity_pk, 32) == 0) {
            if (desc->published > config->consensus.relays[i].published)
                memcpy(&config->consensus.relays[i], desc, sizeof(*desc));
            da_unlock(config);
            return 0;
        }
    }
    if (config->consensus.num_relays < MOOR_MAX_RELAYS) {
        memcpy(&config->consensus.relays[config->consensus.num_relays],
               desc, sizeof(*desc));
        config->consensus.num_relays++;
        ret = 0;
    }
    da_unlock(config);
    return ret;
}

/*
 * Build the raw consensus body bytes (timestamps + relay descriptors).
 * Caller must free *body_out. Returns 0 on success, -1 on error.
 */
static int consensus_body_build(uint8_t **body_out, size_t *body_len_out,
                                const moor_consensus_t *cons) {
    /* Hash the consensus body: timestamps + sorted relay identity keys + bandwidth.
     * This uses ONLY fields that survive the text wire format round-trip and
     * are deterministic across DAs with the same relay set. */
    size_t buf_sz = cons->num_relays * 48 + 64;
    uint8_t *buf = malloc(buf_sz);
    if (!buf) return -1;

    size_t off = 0;
    /* Timestamps (epoch-aligned, identical across DAs) */
    for (int i = 7; i >= 0; i--) buf[off++] = (uint8_t)(cons->valid_after >> (i * 8));
    for (int i = 7; i >= 0; i--) buf[off++] = (uint8_t)(cons->fresh_until >> (i * 8));
    for (int i = 7; i >= 0; i--) buf[off++] = (uint8_t)(cons->valid_until >> (i * 8));

    /* Relay count */
    buf[off++] = (uint8_t)(cons->num_relays >> 24);
    buf[off++] = (uint8_t)(cons->num_relays >> 16);
    buf[off++] = (uint8_t)(cons->num_relays >> 8);
    buf[off++] = (uint8_t)(cons->num_relays);

    /* Relay identity keys (sorted, 32 bytes each) + bandwidth (8 bytes each).
     * These fields survive text serialization perfectly. */
    for (uint32_t i = 0; i < cons->num_relays; i++) {
        if (off + 40 > buf_sz) { free(buf); return -1; }
        memcpy(buf + off, cons->relays[i].identity_pk, 32); off += 32;
        for (int j = 7; j >= 0; j--)
            buf[off++] = (uint8_t)(cons->relays[i].bandwidth >> (j * 8));
    }

    *body_out = buf;
    *body_len_out = off;
    return 0;
}

/*
 * Hash the consensus body (timestamps + relay descriptors) for signing.
 * Wrapper around consensus_body_build: builds body, hashes, frees.
 */
static int consensus_body_hash(uint8_t hash_out[32],
                               const moor_consensus_t *cons) {
    uint8_t *body;
    size_t body_len;
    if (consensus_body_build(&body, &body_len, cons) != 0)
        return -1;
    moor_crypto_hash(hash_out, body, body_len);
    free(body);
    return 0;
}

/*
 * Resolve relay families: for each pair of relays, check if A lists B
 * AND B lists A. If mutual, assign family_id = BLAKE2b(min(A.pk, B.pk)).
 * Also flag BADEXIT relays from DA config.
 */
/* Hash set for O(1) identity_pk → relay index lookup */
#define FAMILY_HT_SIZE 4096
#define FAMILY_HT_MASK (FAMILY_HT_SIZE - 1)

typedef struct {
    uint32_t relay_idx;
    int      occupied;
} family_ht_entry_t;

static uint32_t family_ht_hash(const uint8_t pk[32]) {
    uint64_t key;
    memcpy(&key, pk, 8);
    return (uint32_t)((key * 11400714819323198485ULL) >> 32) & FAMILY_HT_MASK;
}

static void da_resolve_families(moor_da_config_t *config) {
    moor_consensus_t *cons = &config->consensus;

    /* Clear all family_ids first */
    for (uint32_t i = 0; i < cons->num_relays; i++) {
        memset(cons->relays[i].family_id, 0, 32);
    }

    /* Build hash set: identity_pk → relay index for O(1) lookup */
    family_ht_entry_t *ht = calloc(FAMILY_HT_SIZE, sizeof(family_ht_entry_t));
    if (!ht) return; /* degrade gracefully -- no families resolved */

    for (uint32_t i = 0; i < cons->num_relays; i++) {
        uint32_t slot = family_ht_hash(cons->relays[i].identity_pk);
        for (uint32_t j = 0; j < FAMILY_HT_SIZE; j++) {
            uint32_t idx = (slot + j) & FAMILY_HT_MASK;
            if (!ht[idx].occupied) {
                ht[idx].relay_idx = i;
                ht[idx].occupied = 1;
                break;
            }
        }
    }

    /* For each relay, check its declared family members via O(1) lookup.
     * O(n × max_family_members) = O(n × 8) = O(n) */
    static const uint8_t zero[32] = {0};
    for (uint32_t i = 0; i < cons->num_relays; i++) {
        moor_node_descriptor_t *a = &cons->relays[i];
        for (int m = 0; m < a->num_family_members; m++) {
            /* Find relay B by identity_pk via hash set */
            uint32_t slot = family_ht_hash(a->family_members[m]);
            int found_b = -1;
            for (uint32_t j = 0; j < FAMILY_HT_SIZE; j++) {
                uint32_t idx = (slot + j) & FAMILY_HT_MASK;
                if (!ht[idx].occupied) break;
                if (sodium_memcmp(cons->relays[ht[idx].relay_idx].identity_pk,
                                 a->family_members[m], 32) == 0) {
                    found_b = (int)ht[idx].relay_idx;
                    break;
                }
            }
            if (found_b < 0 || (uint32_t)found_b == i) continue;

            moor_node_descriptor_t *b = &cons->relays[found_b];

            /* Does B list A? (check B's family_members for A's pk) */
            int b_lists_a = 0;
            for (int n = 0; n < b->num_family_members; n++) {
                if (sodium_memcmp(b->family_members[n], a->identity_pk, 32) == 0) {
                    b_lists_a = 1;
                    break;
                }
            }
            if (!b_lists_a) continue;

            /* Mutual declaration: assign family_id */
            uint8_t family_input[64];
            if (memcmp(a->identity_pk, b->identity_pk, 32) < 0) {
                memcpy(family_input, a->identity_pk, 32);
                memcpy(family_input + 32, b->identity_pk, 32);
            } else {
                memcpy(family_input, b->identity_pk, 32);
                memcpy(family_input + 32, a->identity_pk, 32);
            }

            uint8_t fid[32];
            moor_crypto_hash(fid, family_input, 64);

            if (sodium_memcmp(a->family_id, zero, 32) == 0)
                memcpy(a->family_id, fid, 32);
            if (sodium_memcmp(b->family_id, zero, 32) == 0)
                memcpy(b->family_id, fid, 32);

            LOG_DEBUG("family: relays %u and %d are mutual siblings", i, found_b);
        }
    }
    free(ht);

    /* Flag BADEXIT relays */
    for (uint32_t i = 0; i < cons->num_relays; i++) {
        for (int b = 0; b < config->num_badexit; b++) {
            if (sodium_memcmp(cons->relays[i].identity_pk,
                             config->badexit_ids[b], 32) == 0) {
                cons->relays[i].flags |= NODE_FLAG_BADEXIT;
                LOG_INFO("DA: flagging relay %u as BADEXIT", i);
                break;
            }
        }
    }
}

/* Sort relays by identity_pk for deterministic consensus body.
 * All DAs with the same relay set produce identical consensus bytes. */
static int relay_sort_by_pk(const void *a, const void *b) {
    return memcmp(((const moor_node_descriptor_t *)a)->identity_pk,
                  ((const moor_node_descriptor_t *)b)->identity_pk, 32);
}

/* Internal lockless version -- caller must hold consensus_lock */
static int da_build_consensus_unlocked(moor_da_config_t *config) {
    /* Shared random: generate commit for this epoch, compute SRV from
     * collected reveals (Tor Prop 250 commit-reveal protocol). */
    moor_da_srv_generate_commit(config);
    moor_da_srv_compute(config);

    /* Epoch-aligned timestamps: all DAs in the same epoch produce
     * identical valid_after/fresh_until/valid_until values.
     * Grace window: if we're within 3 seconds of the NEXT epoch, round up.
     * Prevents body-hash divergence when two DAs' timers straddle the
     * hour boundary (e.g. 23:59:59 vs 00:00:01). */
    uint64_t now = (uint64_t)time(NULL);
    uint64_t epoch = (now / MOOR_CONSENSUS_INTERVAL) * MOOR_CONSENSUS_INTERVAL;
    uint64_t next_epoch = epoch + MOOR_CONSENSUS_INTERVAL;
    if (next_epoch - now <= 3)
        epoch = next_epoch;
    config->consensus.valid_after = epoch;
    config->consensus.fresh_until = epoch + MOOR_CONSENSUS_INTERVAL;
    config->consensus.valid_until = epoch + MOOR_CONSENSUS_INTERVAL * 3;

    /* Evict stale relays that haven't re-registered.
     * Relays re-register every CONSENSUS_INTERVAL/2 (30 min).
     * Threshold: 3 * CONSENSUS_INTERVAL (3 hours) -- allows 6 missed cycles. */
    uint64_t stale_threshold = MOOR_CONSENSUS_INTERVAL * 3;
    uint32_t reaped = 0;
    for (uint32_t i = 0; i < config->consensus.num_relays; ) {
        uint64_t last_seen = config->consensus.relays[i].last_registered;
        if (last_seen == 0) last_seen = config->consensus.relays[i].published;
        if (now > last_seen && now - last_seen > stale_threshold) {
            LOG_WARN("DA: evicting stale relay %s:%u (last seen %llus ago)",
                     config->consensus.relays[i].address,
                     config->consensus.relays[i].or_port,
                     (unsigned long long)(now - last_seen));
            /* Swap with last entry and shrink */
            config->consensus.relays[i] =
                config->consensus.relays[config->consensus.num_relays - 1];
            config->consensus.num_relays--;
            reaped++;
        } else {
            i++;
        }
    }
    if (reaped > 0)
        LOG_INFO("DA: reaped %u stale relay(s)", reaped);

    /* Sort relays by identity_pk so all DAs produce identical body */
    if (config->consensus.num_relays > 1)
        qsort(config->consensus.relays, config->consensus.num_relays,
              sizeof(moor_node_descriptor_t), relay_sort_by_pk);

    /* Copy SRV into consensus for DHT epoch computation */
    memcpy(config->consensus.srv_current, config->srv_current, 32);
    memcpy(config->consensus.srv_previous, config->srv_previous, 32);

    /* Recompute relay flags from measured data -- relays cannot self-assign */
    moor_da_compute_flags_statistical(config);

    /* Tor-aligned: never mutate desc->bandwidth (relay-signed field).
     * DA-adjusted bandwidth is computed on-the-fly via
     * moor_bw_auth_effective(bandwidth, verified_bandwidth) wherever needed.
     * This preserves the relay's descriptor signature through DA sync. */

    /* Tor-aligned: compute bandwidth weights for path selection.
     * These are embedded in the consensus so all clients use identical values.
     * Algorithm from Tor's networkstatus_compute_bw_weights_v10(). */
    {
        int64_t G = 0, M = 0, E = 0, D = 0, T;
        for (uint32_t i = 0; i < config->consensus.num_relays; i++) {
            moor_node_descriptor_t *r = &config->consensus.relays[i];
            int64_t bw = (int64_t)moor_bw_auth_effective(r->bandwidth, r->verified_bandwidth);
            int is_guard = (r->flags & NODE_FLAG_GUARD) != 0;
            int is_exit  = (r->flags & NODE_FLAG_EXIT) != 0;
            if (is_guard && is_exit)      D += bw;
            else if (is_guard)            G += bw;
            else if (is_exit)             E += bw;
            else                          M += bw;
        }
        T = G + M + E + D;
        if (T == 0) T = 1;

        int32_t S = BW_WEIGHT_SCALE;
        int32_t *W = config->consensus.bw_weights;

        if (3 * E >= T && 3 * G >= T) {
            /* Case 1: Neither guards nor exits scarce */
            W[BW_WGG] = (int32_t)((S * (int64_t)(E + M)) / (3 * G));
            W[BW_WMG] = S - W[BW_WGG];
            W[BW_WEE] = (int32_t)((S * (int64_t)(E + G + M)) / (3 * E));
            W[BW_WME] = S - W[BW_WEE];
            W[BW_WGD] = S / 3;
            W[BW_WED] = S / 3;
            W[BW_WMD] = S / 3;
            W[BW_WMM] = S;
        } else if (3 * E < T && 3 * G < T) {
            /* Case 2: Both guards and exits scarce */
            W[BW_WGG] = S;
            W[BW_WMG] = 0;
            W[BW_WEE] = S;
            W[BW_WME] = 0;
            W[BW_WMM] = S;
            if (E < G) {
                W[BW_WED] = S;
                W[BW_WGD] = 0;
            } else {
                W[BW_WED] = 0;
                W[BW_WGD] = S;
            }
            W[BW_WMD] = 0;
        } else if (3 * E < T) {
            /* Case 3a: Exits scarce */
            W[BW_WEE] = S;
            W[BW_WME] = 0;
            W[BW_WGG] = (int32_t)((S * (int64_t)(M + E)) / (3 * G));
            W[BW_WMG] = S - W[BW_WGG];
            W[BW_WGD] = 0;
            W[BW_WED] = S;
            W[BW_WMD] = 0;
            W[BW_WMM] = S;
        } else {
            /* Case 3b: Guards scarce */
            W[BW_WGG] = S;
            W[BW_WMG] = 0;
            W[BW_WEE] = (int32_t)((S * (int64_t)(M + G)) / (3 * E));
            W[BW_WME] = S - W[BW_WEE];
            W[BW_WGD] = S;
            W[BW_WED] = 0;
            W[BW_WMD] = 0;
            W[BW_WMM] = S;
        }

        /* Clamp all weights to [0, S] */
        for (int wi = 0; wi < 8; wi++) {
            if (W[wi] < 0) W[wi] = 0;
            if (W[wi] > S) W[wi] = S;
        }

        LOG_INFO("bw-weights: G=%lld M=%lld E=%lld D=%lld T=%lld "
                 "Wgg=%d Wee=%d Wmg=%d Wme=%d Wmm=%d",
                 (long long)G, (long long)M, (long long)E, (long long)D, (long long)T,
                 W[BW_WGG], W[BW_WEE], W[BW_WMG], W[BW_WME], W[BW_WMM]);
    }

    /* Resolve relay families and flag BADEXIT before signing */
    da_resolve_families(config);

    /* Sign the consensus body with our DA key.
     * Add our signature to the multi-DA signature array. */
    uint8_t body_hash[32];
    if (consensus_body_hash(body_hash, &config->consensus) != 0)
        return -1;

    /* Check if we already have a sig slot, otherwise add one */
    int slot = -1;
    for (uint32_t i = 0; i < config->consensus.num_da_sigs; i++) {
        if (sodium_memcmp(config->consensus.da_sigs[i].identity_pk,
                         config->identity_pk, 32) == 0) {
            slot = (int)i;
            break;
        }
    }
    if (slot < 0) {
        if (config->consensus.num_da_sigs >= MOOR_MAX_DA_AUTHORITIES) {
            LOG_ERROR("DA: too many DA signatures");
            return -1;
        }
        slot = (int)config->consensus.num_da_sigs++;
    }

    memcpy(config->consensus.da_sigs[slot].identity_pk,
           config->identity_pk, 32);
    moor_crypto_sign(config->consensus.da_sigs[slot].signature,
                     body_hash, 32, config->identity_sk);

    /* Hybrid PQ: sign with ML-DSA-65 if PQ keys are available */
    if (!sodium_is_zero(config->pq_identity_pk, MOOR_MLDSA_PK_LEN)) {
        uint8_t *body = NULL;
        size_t body_len = 0;
        if (consensus_body_build(&body, &body_len, &config->consensus) == 0) {
            size_t sig_len = 0;
            if (moor_mldsa_sign(config->consensus.da_sigs[slot].pq_signature,
                                &sig_len, body, body_len,
                                config->pq_identity_sk) == 0) {
                memcpy(config->consensus.da_sigs[slot].pq_pk,
                       config->pq_identity_pk, MOOR_MLDSA_PK_LEN);
                config->consensus.da_sigs[slot].has_pq = 1;
                LOG_INFO("DA: hybrid Ed25519+ML-DSA-65 consensus signature");
            } else {
                config->consensus.da_sigs[slot].has_pq = 0;
                LOG_WARN("DA: ML-DSA-65 signing failed, Ed25519-only");
            }
            free(body);
        } else {
            config->consensus.da_sigs[slot].has_pq = 0;
        }
    } else {
        config->consensus.da_sigs[slot].has_pq = 0;
    }

    LOG_INFO("DA: consensus built with %u relays, %u DA signature(s)%s",
             config->consensus.num_relays, config->consensus.num_da_sigs,
             config->consensus.da_sigs[slot].has_pq ? " [PQ hybrid]" : "");

    /* NOTE: snapshot is NOT taken here. It's taken AFTER vote exchange
     * completes (in the timer callback or after exchange_votes returns),
     * so the published consensus always has the peer's signature too.
     * This prevents clients from fetching a 1-sig consensus. */

    return 0;
}

/* Public API: acquires consensus_lock */
int moor_da_build_consensus(moor_da_config_t *config) {
    da_lock(config);
    int ret = da_build_consensus_unlocked(config);
    da_unlock(config);
    return ret;
}

/* Internal lockless version -- caller must hold consensus_lock */
static void da_update_published_snapshot_unlocked(moor_da_config_t *config) {
    size_t buf_sz = moor_consensus_wire_size(&config->consensus);
    if (buf_sz < 1024) buf_sz = 1024;
    uint8_t *buf = malloc(buf_sz);
    if (!buf) {
        LOG_WARN("DA: snapshot update malloc failed (%zu bytes), serving stale consensus",
                 buf_sz);
    }
    if (buf) {
        int len = moor_consensus_serialize(buf, buf_sz, &config->consensus);
        if (len > 0) {
            /* Atomic swap: install new BEFORE freeing old. If a reader
             * is in the middle of sending published_buf to a client,
             * freeing first would UAF. Swap pointer + length together
             * so readers always see a consistent pair. */
            uint8_t *old = config->published_buf;
            config->published_buf = buf;
            config->published_len = len;
            free(old);
            LOG_DEBUG("DA: published snapshot updated (%d sigs)",
                      config->consensus.num_da_sigs);
        } else {
            free(buf);
        }
    }
}

/* Public API: acquires consensus_lock */
void moor_da_update_published_snapshot(moor_da_config_t *config) {
    da_lock(config);
    da_update_published_snapshot_unlocked(config);
    da_unlock(config);
}

int moor_da_build_microdesc_consensus(moor_microdesc_consensus_t *mc,
                                       const moor_da_config_t *config) {
    const moor_consensus_t *cons = &config->consensus;
    mc->valid_after = cons->valid_after;
    mc->fresh_until = cons->fresh_until;
    mc->valid_until = cons->valid_until;
    mc->num_relays = cons->num_relays;

    for (uint32_t i = 0; i < cons->num_relays && i < MOOR_MAX_RELAYS; i++) {
        const moor_node_descriptor_t *d = &cons->relays[i];
        moor_microdesc_t *m = &mc->relays[i];
        memcpy(m->identity_pk, d->identity_pk, 32);
        memcpy(m->onion_pk, d->onion_pk, 32);
        m->flags = d->flags;
        m->bandwidth = moor_bw_auth_effective(d->bandwidth, d->verified_bandwidth);
        m->features = d->features;
        memcpy(m->family_id, d->family_id, 32);
        m->country_code = d->country_code;
        m->as_number = d->as_number;
        memcpy(m->nickname, d->nickname, 32);
    }

    /* Copy DA signatures (including PQ) from full consensus */
    mc->num_da_sigs = cons->num_da_sigs;
    for (uint32_t i = 0; i < cons->num_da_sigs && i < MOOR_MAX_DA_AUTHORITIES; i++) {
        memcpy(mc->da_sigs[i].signature, cons->da_sigs[i].signature, 64);
        memcpy(mc->da_sigs[i].identity_pk, cons->da_sigs[i].identity_pk, 32);
        mc->da_sigs[i].has_pq = cons->da_sigs[i].has_pq;
        if (cons->da_sigs[i].has_pq) {
            memcpy(mc->da_sigs[i].pq_signature, cons->da_sigs[i].pq_signature,
                   MOOR_MLDSA_SIG_LEN);
            memcpy(mc->da_sigs[i].pq_pk, cons->da_sigs[i].pq_pk, MOOR_MLDSA_PK_LEN);
        }
    }

    LOG_INFO("microdesc consensus built: %u relays", mc->num_relays);
    return 0;
}

int moor_consensus_verify(const moor_consensus_t *cons,
                          const uint8_t *trusted_da_pks,
                          int num_trusted) {
    if (num_trusted <= 0 || !trusted_da_pks) return -1; /* no trust list = reject */

    uint8_t body_hash[32];
    if (consensus_body_hash(body_hash, cons) != 0) return -1;

    int verified = 0;
    /* For 2 DAs: accept 1 valid sig minimum. Strict 2/2 is unreliable
     * because async vote exchange means the published snapshot often
     * has only the local DA's sig when clients fetch it. The security
     * tradeoff: a single compromised DA can forge consensus in a 2-DA
     * setup, but a 2-DA setup already has no Byzantine fault tolerance.
     * For 3+ DAs: strict majority (2/3, 3/5, etc). */
    int majority = (num_trusted <= 2) ? 1 : (num_trusted / 2) + 1;

    for (uint32_t i = 0; i < cons->num_da_sigs; i++) {
        for (int j = 0; j < num_trusted; j++) {
            if (sodium_memcmp(cons->da_sigs[i].identity_pk,
                             trusted_da_pks + j * 32, 32) == 0) {
                /* Trusted DA -- verify its signature */
                if (moor_crypto_sign_verify(cons->da_sigs[i].signature,
                                             body_hash, 32,
                                             cons->da_sigs[i].identity_pk) == 0) {
                    verified++;
                }
                break;
            }
        }
    }

    if (verified >= majority) {
        LOG_INFO("consensus verified: %d/%d trusted DAs signed",
                 verified, num_trusted);
        return 0;
    }

    LOG_ERROR("consensus verification failed: %d/%d signatures (need %d)",
              verified, num_trusted, majority);
    return -1;
}

int moor_consensus_verify_hybrid(const moor_consensus_t *cons,
                                 const moor_trusted_da_key_t *trusted_keys,
                                 int num_trusted) {
    if (num_trusted <= 0 || !trusted_keys) return -1;

    uint8_t body_hash[32];
    if (consensus_body_hash(body_hash, cons) != 0) return -1;

    /* Build raw body for ML-DSA verification (lazy -- only if needed) */
    uint8_t *body = NULL;
    size_t body_len = 0;

    int verified = 0;
    int majority = (num_trusted <= 2) ? 1 : (num_trusted / 2) + 1;

    for (uint32_t i = 0; i < cons->num_da_sigs; i++) {
        for (int j = 0; j < num_trusted; j++) {
            if (sodium_memcmp(cons->da_sigs[i].identity_pk,
                             trusted_keys[j].ed25519_pk, 32) == 0) {
                /* Step 1: Ed25519 verify (cheap, ~10us) */
                if (moor_crypto_sign_verify(cons->da_sigs[i].signature,
                                             body_hash, 32,
                                             cons->da_sigs[i].identity_pk) != 0) {
                    LOG_WARN("hybrid verify: Ed25519 failed for DA sig %u", i);
                    break;
                }

                /* Step 2: ML-DSA verify if both sig and trusted key have PQ */
                if (cons->da_sigs[i].has_pq && trusted_keys[j].has_pq) {
                    /* Verify PQ public key matches trusted key */
                    if (memcmp(cons->da_sigs[i].pq_pk,
                               trusted_keys[j].mldsa_pk,
                               MOOR_MLDSA_PK_LEN) != 0) {
                        LOG_WARN("hybrid verify: PQ pk mismatch for DA sig %u", i);
                        break;
                    }

                    /* Lazy-build raw body */
                    if (!body) {
                        if (consensus_body_build(&body, &body_len, cons) != 0) {
                            return -1;
                        }
                    }

                    if (moor_mldsa_verify(cons->da_sigs[i].pq_signature,
                                          MOOR_MLDSA_SIG_LEN,
                                          body, body_len,
                                          cons->da_sigs[i].pq_pk) != 0) {
                        LOG_WARN("hybrid verify: ML-DSA-65 failed for DA sig %u", i);
                        break;
                    }
                }
                /* Require PQ sig if trusted key has PQ capability */
                if (trusted_keys[j].has_pq && !cons->da_sigs[i].has_pq) {
                    LOG_WARN("hybrid verify: PQ-capable DA %u sent Ed25519-only sig", i);
                    break;
                }

                verified++;
                break;
            }
        }
    }

    free(body);

    if (verified >= majority) {
        LOG_INFO("hybrid consensus verified: %d/%d trusted DAs signed",
                 verified, num_trusted);
        return 0;
    }

    LOG_ERROR("hybrid consensus verification failed: %d/%d signatures (need %d)",
              verified, num_trusted, majority);
    return -1;
}

int moor_da_store_hs(moor_da_config_t *config,
                     const uint8_t address_hash[32],
                     const uint8_t *data, uint32_t data_len) {
    if (data_len > sizeof(config->hs_entries[0].data)) {
        LOG_ERROR("DA: HS descriptor too large");
        return -1;
    }

    /* Check if we already have it */
    for (uint32_t i = 0; i < config->num_hs_entries; i++) {
        if (sodium_memcmp(config->hs_entries[i].address_hash,
                         address_hash, 32) == 0) {
            memcpy(config->hs_entries[i].data, data, data_len);
            config->hs_entries[i].data_len = data_len;
            LOG_INFO("DA: updated HS entry");
            return 0;
        }
    }

    if (config->num_hs_entries >= 64) {
        LOG_ERROR("DA: HS entry table full");
        return -1;
    }

    uint32_t idx = config->num_hs_entries++;
    memcpy(config->hs_entries[idx].address_hash, address_hash, 32);
    memcpy(config->hs_entries[idx].data, data, data_len);
    config->hs_entries[idx].data_len = data_len;
    LOG_INFO("DA: stored HS entry #%u", idx);

    /* Persist to disk so HS descriptors survive DA restarts */
    moor_da_save_hs(config);
    return 0;
}

void moor_da_save_hs(const moor_da_config_t *config) {
    (void)config;
    extern moor_config_t g_config;
    if (!g_config.data_dir[0]) return;
    char path[512], tmp[520];
    snprintf(path, sizeof(path), "%s/hs_store.dat", g_config.data_dir);
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "wb");
    if (!f) return;
    const uint8_t magic[4] = { 'M', 'H', 'S', 'D' };
    const uint8_t ver = 1;
    uint32_t n = config->num_hs_entries;
    fwrite(magic, 4, 1, f);
    fwrite(&ver, 1, 1, f);
    fwrite(&n, 4, 1, f);
    for (uint32_t i = 0; i < n; i++) {
        fwrite(config->hs_entries[i].address_hash, 32, 1, f);
        fwrite(&config->hs_entries[i].data_len, 4, 1, f);
        fwrite(config->hs_entries[i].data, config->hs_entries[i].data_len, 1, f);
    }
    fclose(f);
    rename(tmp, path);
    LOG_DEBUG("DA: saved %u HS entries to disk", n);
}

int moor_da_load_hs(moor_da_config_t *config) {
    extern moor_config_t g_config;
    if (!g_config.data_dir[0]) return -1;
    char path[512];
    snprintf(path, sizeof(path), "%s/hs_store.dat", g_config.data_dir);
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    uint8_t magic[4], ver;
    uint32_t n;
    if (fread(magic, 4, 1, f) != 1 || fread(&ver, 1, 1, f) != 1 ||
        fread(&n, 4, 1, f) != 1) { fclose(f); return -1; }
    if (magic[0] != 'M' || magic[1] != 'H' || magic[2] != 'S' ||
        magic[3] != 'D' || ver != 1 || n > 64) { fclose(f); return -1; }
    uint32_t loaded = 0;
    for (uint32_t i = 0; i < n; i++) {
        uint8_t addr[32]; uint32_t dlen;
        if (fread(addr, 32, 1, f) != 1 || fread(&dlen, 4, 1, f) != 1 ||
            dlen > MOOR_DHT_MAX_DESC_DATA) break;
        uint8_t data[MOOR_DHT_MAX_DESC_DATA];
        if (fread(data, dlen, 1, f) != 1) break;
        if (loaded < 64) {
            memcpy(config->hs_entries[loaded].address_hash, addr, 32);
            memcpy(config->hs_entries[loaded].data, data, dlen);
            config->hs_entries[loaded].data_len = dlen;
            loaded++;
        }
    }
    config->num_hs_entries = loaded;
    fclose(f);
    LOG_INFO("DA: loaded %u HS entries from disk", loaded);
    return 0;
}

const moor_hs_stored_entry_t *moor_da_lookup_hs(
    const moor_da_config_t *config, const uint8_t address_hash[32]) {
    const moor_hs_stored_entry_t *found = NULL;
    for (uint32_t i = 0; i < config->num_hs_entries; i++) {
        if (sodium_memcmp(config->hs_entries[i].address_hash,
                          address_hash, 32) == 0) {
            found = &config->hs_entries[i];
        }
    }
    return found;
}

/*
 * Forward a raw descriptor to all peer DAs (best-effort, fire-and-forget).
 * Peers receive "PROPAGATE\n" + length(4) + descriptor bytes.
 * Does NOT include PoW data — peers trust the originating DA's verification.
 */
static void moor_da_propagate_descriptor(moor_da_config_t *config,
                                          const uint8_t *desc_buf,
                                          uint32_t desc_len) {
    for (int p = 0; p < config->num_peers; p++) {
        int fd = moor_tcp_connect_simple(config->peers[p].address,
                                          config->peers[p].port);
        if (fd < 0) {
            LOG_DEBUG("DA propagate: cannot reach peer %s:%u",
                      config->peers[p].address, config->peers[p].port);
            continue;
        }
        moor_setsockopt_timeo(fd, SO_SNDTIMEO, 2);
        moor_setsockopt_timeo(fd, SO_RCVTIMEO, 2);

        uint8_t hdr[14]; /* "PROPAGATE\n" = 10 + length(4) */
        memcpy(hdr, "PROPAGATE\n", 10);
        hdr[10] = (uint8_t)(desc_len >> 24);
        hdr[11] = (uint8_t)(desc_len >> 16);
        hdr[12] = (uint8_t)(desc_len >> 8);
        hdr[13] = (uint8_t)(desc_len);
        send(fd, (char *)hdr, 14, MSG_NOSIGNAL);
        send(fd, (const char *)desc_buf, desc_len, MSG_NOSIGNAL);

        char resp[16];
        recv(fd, resp, sizeof(resp), 0);
        close(fd);
        LOG_DEBUG("DA: propagated descriptor to %s:%u",
                  config->peers[p].address, config->peers[p].port);
    }
}

/*
 * Forward HS descriptor to all peer DAs (best-effort).
 */
static void moor_da_propagate_hs(moor_da_config_t *config,
                                  const uint8_t *hs_data, uint32_t hs_len) {
    for (int p = 0; p < config->num_peers; p++) {
        int fd = moor_tcp_connect_simple(config->peers[p].address,
                                          config->peers[p].port);
        if (fd < 0) continue;
        moor_setsockopt_timeo(fd, SO_SNDTIMEO, 2);
        moor_setsockopt_timeo(fd, SO_RCVTIMEO, 2);

        uint8_t hdr[17]; /* "HS_PROPAGATE\n" = 13 + length(4) = 17 */
        memcpy(hdr, "HS_PROPAGATE\n", 13);
        hdr[13] = (uint8_t)(hs_len >> 24);
        hdr[14] = (uint8_t)(hs_len >> 16);
        hdr[15] = (uint8_t)(hs_len >> 8);
        hdr[16] = (uint8_t)(hs_len);
        send(fd, (char *)hdr, 17, MSG_NOSIGNAL);
        send(fd, (const char *)hs_data, hs_len, MSG_NOSIGNAL);

        char resp[16];
        recv(fd, resp, sizeof(resp), 0);
        close(fd);
    }
}

/* HTML-escape a string to prevent XSS (#204). Output truncated to out_len-1. */
static void html_escape(char *out, size_t out_len, const char *in) {
    size_t o = 0;
    for (size_t i = 0; in[i] && o + 6 < out_len; i++) {
        switch (in[i]) {
        case '<':  memcpy(out + o, "&lt;", 4);   o += 4; break;
        case '>':  memcpy(out + o, "&gt;", 4);   o += 4; break;
        case '&':  memcpy(out + o, "&amp;", 5);  o += 5; break;
        case '"':  memcpy(out + o, "&quot;", 6); o += 6; break;
        case '\'': memcpy(out + o, "&#39;", 5);  o += 5; break;
        default:   out[o++] = in[i]; break;
        }
    }
    out[o] = '\0';
}

/* JSON-escape a string (#204). Output truncated to out_len-1. */
static void json_escape(char *out, size_t out_len, const char *in) {
    size_t o = 0;
    for (size_t i = 0; in[i] && o + 2 < out_len; i++) {
        if (in[i] == '"' || in[i] == '\\') {
            out[o++] = '\\';
        }
        out[o++] = in[i];
    }
    out[o] = '\0';
}

/*
 * HTTP metrics dashboard: serves network status when DA receives GET /
 */
static void da_serve_metrics(int fd, moor_da_config_t *config) {
    /* Build HTML body into a dynamically sized buffer */
    size_t cap = 32768;
    char *body = malloc(cap);
    if (!body) return;
    size_t off = 0;

#define APPEND(...) do { \
    if (off < cap) { \
        int _w = snprintf(body + off, cap - off, __VA_ARGS__); \
        if (_w > 0 && off + (size_t)_w < cap) off += (size_t)_w; \
    } \
} while(0)

    /* Consensus stats */
    moor_consensus_t *cons = &config->consensus;
    uint32_t nr = cons->num_relays;
    uint64_t total_bw = 0, total_vbw = 0;
    uint32_t n_guard = 0, n_exit = 0, n_fast = 0, n_stable = 0, n_pq = 0;
    for (uint32_t i = 0; i < nr; i++) {
        moor_node_descriptor_t *r = &cons->relays[i];
        total_bw += moor_bw_auth_effective(r->bandwidth, r->verified_bandwidth);
        total_vbw += r->verified_bandwidth;
        if (r->flags & NODE_FLAG_GUARD) n_guard++;
        if (r->flags & NODE_FLAG_EXIT)  n_exit++;
        if (r->flags & NODE_FLAG_FAST)  n_fast++;
        if (r->flags & NODE_FLAG_STABLE) n_stable++;
        if (r->features & NODE_FEATURE_PQ) n_pq++;
    }

    APPEND("<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>MOOR Network Metrics</title>"
        "<style>"
        "*{margin:0;padding:0;box-sizing:border-box}"
        "body{font-family:'Courier New',monospace;background:#0a0e17;color:#c0c8d8;padding:20px}"
        "h1{color:#7fdbca;font-size:1.6em;margin-bottom:4px}"
        ".sub{color:#637777;font-size:0.85em;margin-bottom:20px}"
        ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:24px}"
        ".card{background:#1a1e2e;border:1px solid #2a2e3e;border-radius:6px;padding:14px}"
        ".card .val{font-size:1.8em;color:#c792ea;font-weight:bold}"
        ".card .lbl{font-size:0.75em;color:#637777;text-transform:uppercase;letter-spacing:1px}"
        "table{width:100%%;border-collapse:collapse;margin-top:8px}"
        "th{text-align:left;color:#7fdbca;font-size:0.75em;text-transform:uppercase;"
        "letter-spacing:1px;padding:8px 10px;border-bottom:2px solid #2a2e3e}"
        "td{padding:6px 10px;border-bottom:1px solid #1a1e2e;font-size:0.85em}"
        "tr:hover{background:#1a1e2e}"
        ".flag{display:inline-block;padding:1px 5px;border-radius:3px;font-size:0.7em;"
        "margin-right:3px;font-weight:bold}"
        ".f-guard{background:#1a3a2a;color:#7fdbca}"
        ".f-exit{background:#3a1a2a;color:#ff6b6b}"
        ".f-fast{background:#2a2a1a;color:#ffd700}"
        ".f-stable{background:#1a2a3a;color:#82aaff}"
        ".f-pq{background:#2a1a3a;color:#c792ea}"
        ".f-badexit{background:#4a0a0a;color:#ff2222}"
        ".pk{font-family:monospace;font-size:0.7em;color:#637777}"
        ".bw{color:#c3e88d}"
        ".section{background:#111827;border:1px solid #2a2e3e;border-radius:8px;padding:16px;margin-bottom:20px}"
        ".section h2{color:#82aaff;font-size:1.1em;margin-bottom:10px}"
        "a{color:#7fdbca;text-decoration:none}a:hover{text-decoration:underline}"
        ".da-info{display:flex;gap:20px;flex-wrap:wrap}"
        ".da-item{background:#1a1e2e;border:1px solid #2a2e3e;border-radius:6px;padding:10px 14px}"
        ".da-item .addr{color:#c3e88d;font-weight:bold}"
        "footer{margin-top:30px;color:#3a3e4e;font-size:0.75em;text-align:center}"
        "</style></head><body>");

    /* Header */
    APPEND("<h1>MOOR Network Metrics</h1>");
    APPEND("<div class='sub'>Directory Authority &mdash; %s:%u &mdash; ",
           config->bind_addr, config->dir_port);
    /* Consensus age */
    uint64_t now = (uint64_t)time(NULL);
    if (cons->valid_after > 0) {
        uint64_t age = now - cons->valid_after;
        APPEND("consensus age: %llum %llus &mdash; ",
               (unsigned long long)(age / 60), (unsigned long long)(age % 60));
    }
    APPEND("%u DA signature(s)", cons->num_da_sigs);
    for (uint32_t i = 0; i < cons->num_da_sigs; i++) {
        if (cons->da_sigs[i].has_pq) { APPEND(" [PQ hybrid]"); break; }
    }
    APPEND("</div>");

    /* Overview cards */
    APPEND("<div class='grid'>");
    APPEND("<div class='card'><div class='val'>%u</div><div class='lbl'>Relays</div></div>", nr);
    APPEND("<div class='card'><div class='val'>%u</div><div class='lbl'>Guards</div></div>", n_guard);
    APPEND("<div class='card'><div class='val'>%u</div><div class='lbl'>Exits</div></div>", n_exit);
    APPEND("<div class='card'><div class='val'>%u</div><div class='lbl'>PQ Capable</div></div>", n_pq);
    /* Format bandwidth nicely */
    if (total_bw >= 1000000000ULL)
        APPEND("<div class='card'><div class='val'>%.1f GB/s</div><div class='lbl'>Advertised BW</div></div>",
               (double)total_bw / 1e9);
    else if (total_bw >= 1000000ULL)
        APPEND("<div class='card'><div class='val'>%.1f MB/s</div><div class='lbl'>Advertised BW</div></div>",
               (double)total_bw / 1e6);
    else
        APPEND("<div class='card'><div class='val'>%llu KB/s</div><div class='lbl'>Advertised BW</div></div>",
               (unsigned long long)(total_bw / 1000));
    if (total_vbw > 0) {
        if (total_vbw >= 1000000ULL)
            APPEND("<div class='card'><div class='val'>%.1f MB/s</div><div class='lbl'>Measured BW</div></div>",
                   (double)total_vbw / 1e6);
        else
            APPEND("<div class='card'><div class='val'>%llu KB/s</div><div class='lbl'>Measured BW</div></div>",
                   (unsigned long long)(total_vbw / 1000));
    }
    APPEND("<div class='card'><div class='val'>%u</div><div class='lbl'>Fast</div></div>", n_fast);
    APPEND("<div class='card'><div class='val'>%u</div><div class='lbl'>Stable</div></div>", n_stable);
    APPEND("</div>");

    /* DA peers section */
    if (config->num_peers > 0) {
        APPEND("<div class='section'><h2>Directory Authorities</h2><div class='da-info'>");
        /* Self */
        APPEND("<div class='da-item'><div class='addr'>%s:%u (self)</div>"
               "<div class='pk'>", config->bind_addr, config->dir_port);
        for (int j = 0; j < 8; j++) APPEND("%02x", config->identity_pk[j]);
        APPEND("...</div></div>");
        for (int i = 0; i < config->num_peers; i++) {
            moor_da_peer_t *p = &config->peers[i];
            APPEND("<div class='da-item'><div class='addr'>%s:%u</div>"
                   "<div class='pk'>", p->address, p->port);
            for (int j = 0; j < 8; j++) APPEND("%02x", p->identity_pk[j]);
            APPEND("...</div>");
            if (p->measured_count > 0)
                APPEND("<div style='font-size:0.75em;color:#637777'>measured: %u relays</div>",
                       p->measured_count);
            APPEND("</div>");
        }
        APPEND("</div></div>");
    }

    /* Relay table */
    APPEND("<div class='section'><h2>Relays</h2>");
    APPEND("<table><tr><th>Nickname</th><th>Address</th><th>Flags</th>"
           "<th>Bandwidth</th><th>Country</th><th>Contact</th><th>Identity</th>"
           "<th>KEM</th><th>Falcon</th><th>Uptime</th></tr>");
    for (uint32_t i = 0; i < nr; i++) {
        moor_node_descriptor_t *r = &cons->relays[i];
        { char esc_nick[128], esc_addr[256];
          html_escape(esc_nick, sizeof(esc_nick), r->nickname[0] ? r->nickname : "Unnamed");
          html_escape(esc_addr, sizeof(esc_addr), r->address);
          APPEND("<tr><td>%s</td>", esc_nick);
          APPEND("<td>%s:%u</td><td>", esc_addr, r->or_port); }
        /* Flags */
        if (r->flags & NODE_FLAG_GUARD)  APPEND("<span class='flag f-guard'>Guard</span>");
        if (r->flags & NODE_FLAG_EXIT)   APPEND("<span class='flag f-exit'>Exit</span>");
        if (r->flags & NODE_FLAG_FAST)   APPEND("<span class='flag f-fast'>Fast</span>");
        if (r->flags & NODE_FLAG_STABLE) APPEND("<span class='flag f-stable'>Stable</span>");
        if (r->flags & NODE_FLAG_HSDIR)  APPEND("<span class='flag f-stable'>HSDir</span>");
        if (r->features & NODE_FEATURE_PQ) APPEND("<span class='flag f-pq'>PQ</span>");
        if (r->flags & NODE_FLAG_BADEXIT) APPEND("<span class='flag f-badexit'>BadExit</span>");
        APPEND("</td>");
        /* Bandwidth: measured is truth, advertised is self-reported */
        APPEND("<td class='bw'>");
        if (r->verified_bandwidth > 0) {
            if (r->verified_bandwidth >= 1000000)
                APPEND("%.1f MB/s", (double)r->verified_bandwidth / 1e6);
            else
                APPEND("%llu KB/s", (unsigned long long)(r->verified_bandwidth / 1000));
        } else {
            APPEND("<span style='color:#637777'>unmeasured</span>");
        }
        APPEND(" <span style='color:#637777'>(adv: ");
        if (r->bandwidth >= 1000000)
            APPEND("%.1f MB/s", (double)r->bandwidth / 1e6);
        else
            APPEND("%llu KB/s", (unsigned long long)(r->bandwidth / 1000));
        APPEND(")</span>");
        APPEND("</td>");
        /* Country */
        char cc[3] = "??";
        if (r->country_code) moor_geoip_unpack_country(r->country_code, cc);
        APPEND("<td>%s</td>", cc);
        /* Contact info */
        { char esc_contact[768];
          html_escape(esc_contact, sizeof(esc_contact),
                      r->contact_info[0] ? r->contact_info : "");
          APPEND("<td style='font-size:0.75em;color:#637777'>%s</td>", esc_contact); }
        /* Identity fingerprint (first 8 bytes hex) */
        APPEND("<td class='pk'>");
        for (int j = 0; j < 8; j++) APPEND("%02x", r->identity_pk[j]);
        APPEND("...</td>");
        /* KEM / Falcon key digests — show first 6 bytes of each raw pk
         * so operators can visually confirm keys rotated on fleet upgrade. */
        int kem_any = 0, fal_any = 0;
        for (int j = 0; j < 6 && j < (int)sizeof(r->kem_pk); j++)
            if (r->kem_pk[j]) { kem_any = 1; break; }
        for (int j = 0; j < 6 && j < (int)sizeof(r->falcon_pk); j++)
            if (r->falcon_pk[j]) { fal_any = 1; break; }
        APPEND("<td class='pk'>");
        if (kem_any) {
            for (int j = 0; j < 6; j++) APPEND("%02x", r->kem_pk[j]);
            APPEND("...");
        } else {
            APPEND("<span style='color:#637777'>-</span>");
        }
        APPEND("</td><td class='pk'>");
        if (fal_any) {
            for (int j = 0; j < 6; j++) APPEND("%02x", r->falcon_pk[j]);
            APPEND("...");
        } else {
            APPEND("<span style='color:#637777'>-</span>");
        }
        APPEND("</td>");
        /* Uptime (use first_seen if available, else published) */
        uint64_t up_base = r->first_seen ? r->first_seen : r->published;
        if (up_base > 0 && now > up_base) {
            uint64_t up = now - up_base;
            if (up >= 86400)
                APPEND("<td>%llud %lluh</td>",
                       (unsigned long long)(up / 86400),
                       (unsigned long long)((up % 86400) / 3600));
            else if (up >= 3600)
                APPEND("<td>%lluh %llum</td>",
                       (unsigned long long)(up / 3600),
                       (unsigned long long)((up % 3600) / 60));
            else
                APPEND("<td>%llum</td>", (unsigned long long)(up / 60));
        } else {
            APPEND("<td>-</td>");
        }
        APPEND("</tr>");
    }
    APPEND("</table></div>");

    /* Hidden services count */
    APPEND("<div class='section'><h2>Hidden Services</h2>");
    APPEND("<div class='grid'>");
    APPEND("<div class='card'><div class='val'>%u</div>"
           "<div class='lbl'>Published Descriptors</div></div>", config->num_hs_entries);
    APPEND("</div></div>");

    APPEND("<footer>MOOR %s &mdash; metrics auto-refresh every 30s</footer>", MOOR_VERSION_STRING);
    APPEND("<script>setTimeout(function(){location.reload()},30000)</script>");
    APPEND("</body></html>");

#undef APPEND

    /* Send HTTP response */
    char hdr[256];
    int hlen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "Cache-Control: no-cache\r\n"
        "\r\n", off);
    send(fd, hdr, (size_t)hlen, MSG_NOSIGNAL);
    /* Send body in chunks to handle large pages */
    size_t sent = 0;
    while (sent < off) {
        size_t chunk = off - sent;
        if (chunk > 16384) chunk = 16384;
        ssize_t w = send(fd, body + sent, chunk, MSG_NOSIGNAL);
        if (w <= 0) break;
        sent += (size_t)w;
    }
    free(body);
    shutdown(fd, SHUT_WR);
    /* Drain client close to avoid RST */
    char drain[64];
    while (recv(fd, drain, sizeof(drain), 0) > 0) {}
}

/* Serve JSON metrics for programmatic consumption */
static void da_serve_metrics_json(int fd, moor_da_config_t *config) {
    size_t cap = 65536; /* enlarged for large relay lists (#203) */
    char *body = malloc(cap);
    if (!body) return;
    size_t off = 0;

#undef APPEND
#define APPEND(...) do { \
    if (off < cap) { \
        int _w = snprintf(body + off, cap - off, __VA_ARGS__); \
        if (_w > 0 && off + (size_t)_w < cap) off += (size_t)_w; \
    } \
} while(0)

    moor_consensus_t *cons = &config->consensus;
    uint32_t nr = cons->num_relays;
    uint64_t total_bw = 0;
    for (uint32_t i = 0; i < nr; i++)
        total_bw += moor_bw_auth_effective(cons->relays[i].bandwidth,
                                           cons->relays[i].verified_bandwidth);

    APPEND("{\"version\":\"%s\",\"relays\":%u,\"total_bandwidth\":%llu,"
           "\"da_signatures\":%u,\"hs_descriptors\":%u,\"consensus_age\":%llu,"
           "\"relay_list\":[",
           MOOR_VERSION_STRING, nr, (unsigned long long)total_bw,
           cons->num_da_sigs, config->num_hs_entries,
           cons->valid_after > 0 ? (unsigned long long)((uint64_t)time(NULL) - cons->valid_after) : 0ULL);

    for (uint32_t i = 0; i < nr; i++) {
        moor_node_descriptor_t *r = &cons->relays[i];
        char cc[3] = "??";
        if (r->country_code) moor_geoip_unpack_country(r->country_code, cc);
        if (i > 0) APPEND(",");
        { char esc_nick[128], esc_addr[256], esc_contact[256];
          json_escape(esc_nick, sizeof(esc_nick), r->nickname[0] ? r->nickname : "Unnamed");
          json_escape(esc_addr, sizeof(esc_addr), r->address);
          json_escape(esc_contact, sizeof(esc_contact), r->contact_info);
        APPEND("{\"nickname\":\"%s\",\"address\":\"%s\",\"or_port\":%u,"
               "\"bandwidth\":%llu,\"verified_bandwidth\":%llu,"
               "\"flags\":%u,\"features\":%u,\"country\":\"%s\","
               "\"contact\":\"%s\","
               "\"published\":%llu,\"first_seen\":%llu,\"identity\":\"",
               esc_nick,
               esc_addr, r->or_port,
               (unsigned long long)r->bandwidth,
               (unsigned long long)r->verified_bandwidth,
               r->flags, r->features, cc,
               esc_contact,
               (unsigned long long)r->published,
               (unsigned long long)r->first_seen); }
        for (int j = 0; j < 32; j++) APPEND("%02x", r->identity_pk[j]);
        APPEND("\"}");
    }
    APPEND("]}");

#undef APPEND

    char hdr[256];
    int hlen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "\r\n", off);
    send(fd, hdr, (size_t)hlen, MSG_NOSIGNAL);
    send(fd, body, off, MSG_NOSIGNAL);
    free(body);
    shutdown(fd, SHUT_WR);
    char drain[64];
    while (recv(fd, drain, sizeof(drain), 0) > 0) {}
}

/*
 * DA request handler: simple text protocol over TCP.
 * Commands:
 *   "PUBLISH\n" + length(4) + descriptor_data  → add relay
 *   "CONSENSUS\n"                               → return consensus
 *   "HS_PUBLISH\n" + length(4) + hs_desc_data   → publish HS descriptor
 *   "HS_LOOKUP\n" + address_hash(32)            → return HS descriptor
 *   "PROPAGATE\n" + length(4) + descriptor      → flooded relay descriptor from peer DA
 *   "HS_PROPAGATE\n" + length(4) + hs_data      → flooded HS descriptor from peer DA
 *   "GET /"                                      → HTTP metrics dashboard
 */
/* Check if a client fd comes from a known DA peer (by IP) */
static int da_is_peer(int client_fd, const moor_da_config_t *config) {
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    if (getpeername(client_fd, (struct sockaddr *)&addr, &addrlen) != 0)
        return 0;
    char client_ip[64] = "";
    if (addr.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&addr;
        inet_ntop(AF_INET, &s->sin_addr, client_ip, sizeof(client_ip));
    } else if (addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&addr;
        inet_ntop(AF_INET6, &s6->sin6_addr, client_ip, sizeof(client_ip));
    }
    for (int i = 0; i < config->num_peers; i++) {
        if (strcmp(config->peers[i].address, client_ip) == 0)
            return 1;
    }
    return 0;
}

/* Core dispatch — shared between blocking and bufferevent entry points */
static int da_dispatch_request(int client_fd, moor_da_config_t *config,
                                const char *cmd_buf, ssize_t n);

int moor_da_handle_request_with_prefix(int client_fd, moor_da_config_t *config,
                                        const char *prefix, size_t prefix_len) {
    char cmd_buf[64];
    memset(cmd_buf, 0, sizeof(cmd_buf));
    ssize_t n = (ssize_t)prefix_len;
    if (n > (ssize_t)(sizeof(cmd_buf) - 1))
        n = (ssize_t)(sizeof(cmd_buf) - 1);
    memcpy(cmd_buf, prefix, (size_t)n);

    /* Restore blocking mode (bufferevent set non-blocking) */
#ifndef _WIN32
    int flags = fcntl(client_fd, F_GETFL, 0);
    if (flags >= 0) fcntl(client_fd, F_SETFL, flags & ~O_NONBLOCK);
#endif
    moor_setsockopt_timeo(client_fd, SO_RCVTIMEO, 10);
    moor_setsockopt_timeo(client_fd, SO_SNDTIMEO, 10);

    return da_dispatch_request(client_fd, config, cmd_buf, n);
}

int moor_da_handle_request(int client_fd, moor_da_config_t *config) {
    char cmd_buf[64];
    memset(cmd_buf, 0, sizeof(cmd_buf));

    ssize_t n = recv(client_fd, cmd_buf, sizeof(cmd_buf) - 1, 0);
    if (n <= 0) return -1;

    return da_dispatch_request(client_fd, config, cmd_buf, n);
}

static int da_dispatch_request(int client_fd, moor_da_config_t *config,
                                const char *cmd_buf, ssize_t n) {

    /* HTTP metrics dashboard -- lock to safely iterate relay list.
     * Tighten send timeout: a slow-read attacker could hold the
     * consensus lock for the full 10s socket timeout, blocking ALL
     * relay registrations and vote exchange.  2s is enough for any
     * legitimate browser to accept the dashboard HTML. */
    if (n >= 5 && strncmp(cmd_buf, "GET /", 5) == 0) {
        moor_setsockopt_timeo(client_fd, SO_SNDTIMEO, 2);
        da_lock(config);
        if (strstr(cmd_buf, "/api") || strstr(cmd_buf, "/json"))
            da_serve_metrics_json(client_fd, config);
        else
            da_serve_metrics(client_fd, config);
        da_unlock(config);
        return 0;
    }

    /* Encrypted DA-to-DA channel: handles SYNC_RELAYS (and future cmds).
     * Uses Noise_IK + PQ Kyber — same handshake as relay connections. */
    if (strncmp(cmd_buf, "DA_LINK\n", 8) == 0) {
        da_encrypted_channel_t ch;
        uint8_t peer_pk[32];
        /* Pass any extra bytes beyond "DA_LINK\n" that the initial recv
         * may have consumed (TCP coalescing into Noise msg1 bytes). */
        size_t extra_len = (n > 8) ? (size_t)(n - 8) : 0;
        const uint8_t *extra_data = extra_len ?
            (const uint8_t *)(cmd_buf + 8) : NULL;
        if (da_channel_accept(&ch, client_fd, config->identity_pk,
                              config->identity_sk, config, peer_pk,
                              extra_data, extra_len) != 0) {
            LOG_WARN("DA: Noise_IK+PQ channel handshake failed");
            return -1;
        }

        /* Read encrypted command from peer */
        uint8_t *cmd_data = NULL;
        ssize_t cmd_len = da_channel_recv(&ch, &cmd_data);
        if (cmd_len <= 0 || !cmd_data) {
            da_channel_close(&ch);
            return -1;
        }

        if (cmd_len >= 11 && memcmp(cmd_data, "SYNC_RELAYS", 11) == 0) {
            da_lock(config);
            /* Build response: count(4) + [len(2) + descriptor]... */
            /* Per-relay wire budget: V2+V3+V4+V5+V6+V7 ≈ 1800 bytes,
             * V8 adds ~1650 (Falcon pk + sig). Round to 4096 per relay. */
            size_t resp_sz = 4;
            for (uint32_t i = 0; i < config->consensus.num_relays; i++)
                resp_sz += 2 + 4096; /* overestimate per relay, covers V8 Falcon */
            uint8_t *resp = malloc(resp_sz);
            if (resp) {
                uint32_t count = config->consensus.num_relays;
                resp[0] = (uint8_t)(count >> 24);
                resp[1] = (uint8_t)(count >> 16);
                resp[2] = (uint8_t)(count >> 8);
                resp[3] = (uint8_t)(count);
                size_t off = 4;
                for (uint32_t i = 0; i < count; i++) {
                    int dlen = moor_node_descriptor_serialize(
                        resp + off + 2, resp_sz - off - 2,
                        &config->consensus.relays[i]);
                    if (dlen <= 0) continue;
                    resp[off] = (uint8_t)(dlen >> 8);
                    resp[off + 1] = (uint8_t)(dlen);
                    off += 2 + dlen;
                }
                da_channel_send(&ch, resp, off);
                free(resp);
                LOG_INFO("DA: encrypted SYNC_RELAYS sent %u descriptors", count);
            }
            da_unlock(config);
        }

        free(cmd_data);
        /* Don't close fd — caller closes it. Just wipe keys. */
        moor_crypto_wipe(ch.send_key, 32);
        moor_crypto_wipe(ch.recv_key, 32);
        return 0;
    }

    if (strncmp(cmd_buf, "PUBLISH\n", 8) == 0) {
        /* Per-IP rate limit on PUBLISH to prevent descriptor flooding (#CWE-400) */
        {
            char peer_ip_rl[INET6_ADDRSTRLEN] = {0};
            struct sockaddr_storage pss;
            socklen_t plen = sizeof(pss);
            if (getpeername(client_fd, (struct sockaddr *)&pss, &plen) == 0) {
                if (pss.ss_family == AF_INET6)
                    inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&pss)->sin6_addr,
                              peer_ip_rl, sizeof(peer_ip_rl));
                else
                    inet_ntop(AF_INET, &((struct sockaddr_in *)&pss)->sin_addr,
                              peer_ip_rl, sizeof(peer_ip_rl));
            }
            if (peer_ip_rl[0] && !moor_ratelimit_check(peer_ip_rl, MOOR_RL_PUBLISH)) {
                LOG_WARN("DA: PUBLISH rate limited for %s", peer_ip_rl);
                send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
                return 0;
            }
        }
        /* Read length + descriptor */
        uint8_t *data = (uint8_t *)cmd_buf + 8;
        size_t remaining = n - 8;

        if (remaining < 4) return -1;
        uint32_t len = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                       ((uint32_t)data[2] << 8) | data[3];
        data += 4;
        remaining -= 4;

        if (len > 8192) {
            LOG_ERROR("DA: PUBLISH descriptor too large (%u)", len);
            return -1;
        }
        uint8_t *desc_buf = malloc(len);
        if (!desc_buf) return -1;

        /* Copy what we already have */
        size_t copied = (remaining < len) ? remaining : len;
        memcpy(desc_buf, data, copied);

        /* Read rest if needed */
        while (copied < len) {
            n = recv(client_fd, (char *)desc_buf + copied, len - copied, 0);
            if (n <= 0) { free(desc_buf); return -1; }
            copied += n;
        }

        moor_node_descriptor_t desc;
        int desc_len = moor_node_descriptor_deserialize(&desc, desc_buf, len);
        if (desc_len > 0) {
            /* Verify source IP matches advertised address. Fail-closed:
             * if getpeername fails we cannot verify, so reject -- otherwise
             * a descriptor advertising any IP would be trusted whenever the
             * kernel refuses the lookup (e.g. socket torn down under us). */
            {
                struct sockaddr_storage peer_ss;
                socklen_t peer_len = sizeof(peer_ss);
                if (getpeername(client_fd, (struct sockaddr *)&peer_ss,
                                &peer_len) != 0) {
                    LOG_WARN("DA: rejecting relay: getpeername failed: %s",
                             strerror(errno));
                    send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
                    free(desc_buf);
                    return 0;
                }
                char peer_ip[INET6_ADDRSTRLEN];
                if (peer_ss.ss_family == AF_INET6) {
                    struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&peer_ss;
                    inet_ntop(AF_INET6, &a6->sin6_addr,
                              peer_ip, sizeof(peer_ip));
                } else {
                    struct sockaddr_in *a4 = (struct sockaddr_in *)&peer_ss;
                    inet_ntop(AF_INET, &a4->sin_addr,
                              peer_ip, sizeof(peer_ip));
                }
                if (strcmp(peer_ip, desc.address) != 0 &&
                    (desc.address6[0] == '\0' ||
                     strcmp(peer_ip, desc.address6) != 0)) {
                    LOG_WARN("DA: rejecting relay: source IP %s != advertised %s/%s",
                             peer_ip, desc.address,
                             desc.address6[0] ? desc.address6 : "none");
                    send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
                    free(desc_buf);
                    return 0;
                }
            }
            /* Verify PoW -- always required (minimum = default difficulty) */
            size_t remaining = len - (size_t)desc_len;
            int pow_diff = config->pow_difficulty >= MOOR_POW_DEFAULT_DIFFICULTY ?
                           config->pow_difficulty : MOOR_POW_DEFAULT_DIFFICULTY;
            if (remaining < 16) {
                LOG_WARN("DA: rejecting relay with missing PoW data");
                send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
                free(desc_buf);
                return 0;
            }
            if (remaining >= 16) {
                uint8_t *pow_data = desc_buf + desc_len;
                uint64_t pow_nonce = ((uint64_t)pow_data[0] << 56) |
                                     ((uint64_t)pow_data[1] << 48) |
                                     ((uint64_t)pow_data[2] << 40) |
                                     ((uint64_t)pow_data[3] << 32) |
                                     ((uint64_t)pow_data[4] << 24) |
                                     ((uint64_t)pow_data[5] << 16) |
                                     ((uint64_t)pow_data[6] << 8) |
                                     pow_data[7];
                uint64_t pow_ts   = ((uint64_t)pow_data[8] << 56) |
                                     ((uint64_t)pow_data[9] << 48) |
                                     ((uint64_t)pow_data[10] << 40) |
                                     ((uint64_t)pow_data[11] << 32) |
                                     ((uint64_t)pow_data[12] << 24) |
                                     ((uint64_t)pow_data[13] << 16) |
                                     ((uint64_t)pow_data[14] << 8) |
                                     pow_data[15];
                if (moor_pow_verify(desc.identity_pk, pow_nonce,
                                     pow_ts, pow_diff, 0) != 0) {
                    LOG_WARN("DA: rejecting relay with invalid PoW");
                    send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
                    free(desc_buf);
                    return 0;
                }
                LOG_INFO("DA: PoW verified (difficulty %d)", pow_diff);
            }
            da_lock(config);
            da_add_relay_unlocked(config, &desc);
            da_build_consensus_unlocked(config);
            da_update_published_snapshot_unlocked(config);
            da_unlock(config);
            /* Reply immediately — don't block the client on peer I/O */
            send(client_fd, "OK\n", 3, MSG_NOSIGNAL);
            /* Propagate + vote exchange in a background thread so the
             * event loop stays responsive for PUBLISH/CONSENSUS from
             * other relays and clients.  Thread owns desc_buf. */
            {
                da_propagate_ctx_t *pctx = malloc(sizeof(*pctx));
                if (pctx) {
                    pctx->config = config;
                    pctx->desc_buf = desc_buf;
                    pctx->desc_len = (uint32_t)desc_len;
                    desc_buf = NULL; /* thread owns it now */
                    pthread_t pt;
                    if (pthread_create(&pt, NULL, da_propagate_thread, pctx) == 0) {
                        pthread_detach(pt);
                    } else {
                        /* Fallback: run inline if thread creation fails */
                        da_propagate_thread(pctx);
                    }
                }
            }
        } else {
            LOG_WARN("DA: PUBLISH descriptor parse failed (len=%u, desc_len=%d)",
                     len, desc_len);
            send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
        }
        free(desc_buf);
    }
    else if (strncmp(cmd_buf, "CONSENSUS\n", 10) == 0) {
        /* Serve the published snapshot whose signatures match the body.
         * Lock to safely read published_buf/published_len. */
        da_lock(config);
        if (config->published_buf && config->published_len > 0) {
            int len = config->published_len;
            uint8_t len_buf[4];
            len_buf[0] = (uint8_t)(len >> 24);
            len_buf[1] = (uint8_t)(len >> 16);
            len_buf[2] = (uint8_t)(len >> 8);
            len_buf[3] = (uint8_t)(len);
            if (send(client_fd, (char *)len_buf, 4, MSG_NOSIGNAL) != 4 ||
                send(client_fd, (char *)config->published_buf, len, MSG_NOSIGNAL) != len)
                LOG_DEBUG("consensus send failed (fd=%d)", client_fd);
        } else {
            send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
        }
        da_unlock(config);
    }
    else if (strncmp(cmd_buf, "MICRODESC\n", 10) == 0) {
        /* Build and return microdescriptor consensus */
        da_lock(config);
        moor_microdesc_consensus_t *mc = calloc(1, sizeof(moor_microdesc_consensus_t));
        if (!mc) { da_unlock(config); return -1; }
        if (moor_microdesc_consensus_init(mc, config->consensus.num_relays) != 0) {
            free(mc);
            da_unlock(config);
            return -1;
        }
        moor_da_build_microdesc_consensus(mc, config);
        /* Account for PQ signature data in buffer size */
        size_t pq_extra = 0;
        for (uint32_t s = 0; s < mc->num_da_sigs; s++) {
            if (mc->da_sigs[s].has_pq)
                pq_extra += 1 + MOOR_MLDSA_SIG_LEN + MOOR_MLDSA_PK_LEN;
        }
        size_t md_sz = 32 + (size_t)mc->num_relays * 150 + 4 +
                        (size_t)mc->num_da_sigs * 97 + pq_extra;
        if (md_sz < 1024) md_sz = 1024;
        uint8_t *buf = malloc(md_sz);
        if (!buf) { moor_microdesc_consensus_cleanup(mc); free(mc); da_unlock(config); return -1; }
        int len = moor_microdesc_consensus_serialize(buf, md_sz, mc);
        moor_microdesc_consensus_cleanup(mc);
        free(mc);
        da_unlock(config);
        if (len > 0) {
            uint8_t len_buf[4];
            len_buf[0] = (uint8_t)(len >> 24);
            len_buf[1] = (uint8_t)(len >> 16);
            len_buf[2] = (uint8_t)(len >> 8);
            len_buf[3] = (uint8_t)(len);
            send(client_fd, (char *)len_buf, 4, MSG_NOSIGNAL);
            send(client_fd, (char *)buf, len, MSG_NOSIGNAL);
        } else {
            send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
        }
        free(buf);
    }
    else if (strncmp(cmd_buf, "HS_PUBLISH\n", 11) == 0) {
        /* Per-IP rate limit on HS_PUBLISH (#CWE-400) */
        {
            char peer_ip_rl[INET6_ADDRSTRLEN] = {0};
            struct sockaddr_storage pss;
            socklen_t plen = sizeof(pss);
            if (getpeername(client_fd, (struct sockaddr *)&pss, &plen) == 0) {
                if (pss.ss_family == AF_INET6)
                    inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&pss)->sin6_addr,
                              peer_ip_rl, sizeof(peer_ip_rl));
                else
                    inet_ntop(AF_INET, &((struct sockaddr_in *)&pss)->sin_addr,
                              peer_ip_rl, sizeof(peer_ip_rl));
            }
            if (peer_ip_rl[0] && !moor_ratelimit_check(peer_ip_rl, MOOR_RL_PUBLISH)) {
                LOG_WARN("DA: HS_PUBLISH rate limited for %s", peer_ip_rl);
                send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
                return 0;
            }
        }
        uint8_t *data = (uint8_t *)cmd_buf + 11;
        size_t remaining = n - 11;

        /* Read length prefix (may need additional recv if split) */
        uint8_t len_hdr[4];
        size_t len_got = (remaining >= 4) ? 4 : remaining;
        memcpy(len_hdr, data, len_got);
        while (len_got < 4) {
            ssize_t r = recv(client_fd, (char *)len_hdr + len_got, 4 - len_got, 0);
            if (r <= 0) return -1;
            len_got += r;
        }
        uint32_t len = ((uint32_t)len_hdr[0] << 24) | ((uint32_t)len_hdr[1] << 16) |
                       ((uint32_t)len_hdr[2] << 8) | len_hdr[3];
        data += (remaining >= 4) ? 4 : remaining;
        remaining -= (remaining >= 4) ? 4 : remaining;

        if (len > MOOR_DHT_MAX_DESC_DATA || len < 32) { send(client_fd, "ERR\n", 4, MSG_NOSIGNAL); return -1; }

        uint8_t *hs_buf = malloc(len);
        if (!hs_buf) return -1;
        size_t copied = (remaining < len) ? remaining : len;
        memcpy(hs_buf, data, copied);
        while (copied < len) {
            n = recv(client_fd, (char *)hs_buf + copied, len - copied, 0);
            if (n <= 0) { free(hs_buf); return -1; }
            copied += n;
        }

        /* First 32 bytes are the address_hash; rest is opaque encrypted data */
        uint8_t addr_hash[32];
        memcpy(addr_hash, hs_buf, 32);
        da_lock(config);
        if (moor_da_store_hs(config, addr_hash, hs_buf, len) == 0) {
            da_unlock(config);
            send(client_fd, "OK\n", 3, MSG_NOSIGNAL);
            /* Flood HS descriptor to peer DAs */
            if (config->num_peers > 0)
                moor_da_propagate_hs(config, hs_buf, len);
        } else {
            da_unlock(config);
            send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
        }
        free(hs_buf);
    }
    else if (strncmp(cmd_buf, "HS_LOOKUP\n", 10) == 0) {
        uint8_t *data = (uint8_t *)cmd_buf + 10;
        size_t remaining = n - 10;

        uint8_t addr_hash[32];
        if (remaining >= 32) {
            memcpy(addr_hash, data, 32);
        } else {
            memcpy(addr_hash, data, remaining);
            size_t got = remaining;
            while (got < 32) {
                n = recv(client_fd, (char *)addr_hash + got, 32 - got, 0);
                if (n <= 0) return -1;
                got += n;
            }
        }

        da_lock(config);
        const moor_hs_stored_entry_t *found = moor_da_lookup_hs(config, addr_hash);
        if (found && found->data_len > 0) {
            uint32_t len = found->data_len;
            uint8_t len_buf[4];
            len_buf[0] = (uint8_t)(len >> 24);
            len_buf[1] = (uint8_t)(len >> 16);
            len_buf[2] = (uint8_t)(len >> 8);
            len_buf[3] = (uint8_t)(len);
            send(client_fd, (char *)len_buf, 4, MSG_NOSIGNAL);
            send(client_fd, (char *)found->data, len, MSG_NOSIGNAL);
        } else {
            send(client_fd, "NONE\n", 5, MSG_NOSIGNAL);
        }
        da_unlock(config);
    }
    else if (strncmp(cmd_buf, "VOTE\n", 5) == 0) {
        /* Reject from non-peer: only trusted DAs may send votes */
        if (!da_is_peer(client_fd, config)) {
            send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
            return 0;
        }
        /*
         * Vote exchange: peer DA sends its signature + identity_pk.
         * Wire format: "VOTE\n" + identity_pk(32) + signature(64) = 96 bytes
         * We merge it into our consensus's da_sigs array.
         */
        uint8_t *data = (uint8_t *)cmd_buf + 5;
        size_t remaining = n - 5;

        uint8_t vote_buf[128]; /* body_hash(32) + identity_pk(32) + sig(64) */
        size_t got = (remaining < 128) ? remaining : 128;
        memcpy(vote_buf, data, got);
        while (got < 128) {
            ssize_t r = recv(client_fd, (char *)vote_buf + got, 128 - got, 0);
            if (r <= 0) return -1;
            got += r;
        }

        uint8_t peer_body_hash[32], peer_pk[32], peer_sig[64];
        memcpy(peer_body_hash, vote_buf, 32);
        memcpy(peer_pk, vote_buf + 32, 32);
        memcpy(peer_sig, vote_buf + 64, 64);

        da_lock(config);
        /* Verify signature against the body hash the SENDER included.
         * Then check if their body hash matches ours — if not, the
         * consensus bodies diverged and we reject (not a valid co-sign). */
        if (moor_crypto_sign_verify(peer_sig, peer_body_hash, 32, peer_pk) != 0) {
            da_unlock(config);
            LOG_WARN("DA: rejecting invalid vote (bad signature)");
            send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
            return 0;
        }
        uint8_t our_body_hash[32];
        if (consensus_body_hash(our_body_hash, &config->consensus) != 0 ||
            sodium_memcmp(our_body_hash, peer_body_hash, 32) != 0) {
            /* Bodies diverged — our relay set differs from peer's.
             * Rebuild consensus from current relay set, then re-exchange.
             * Without this, the DAs stay diverged until the next sync
             * timer fires (5 minutes), creating a split-brain window. */
            da_build_consensus_unlocked(config);
            da_update_published_snapshot_unlocked(config);
            da_unlock(config);
            LOG_WARN("DA: vote bodies diverged, rebuilt consensus");
            send(client_fd, "DIVERGED\n", 9, MSG_NOSIGNAL);
            return 0;
        }

        /* Verify peer_pk belongs to a configured DA peer (not self) */
        {
            int trusted = 0;
            /* Reject self-votes from network — DA signs locally */
            if (sodium_memcmp(config->identity_pk, peer_pk, 32) == 0) {
                da_unlock(config);
                LOG_WARN("DA: rejecting self-vote received over network");
                send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
                return 0;
            }
            for (int p = 0; p < config->num_peers; p++) {
                if (sodium_memcmp(config->peers[p].identity_pk,
                                  peer_pk, 32) == 0) {
                    trusted = 1;
                    break;
                }
            }
            if (!trusted) {
                da_unlock(config);
                LOG_WARN("DA: rejecting vote from unknown/untrusted peer");
                send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
                return 0;
            }
        }

        /* Merge: find existing slot or add new */
        int slot = -1;
        for (uint32_t i = 0; i < config->consensus.num_da_sigs; i++) {
            if (sodium_memcmp(config->consensus.da_sigs[i].identity_pk,
                             peer_pk, 32) == 0) {
                slot = (int)i;
                break;
            }
        }
        if (slot < 0) {
            if (config->consensus.num_da_sigs >= MOOR_MAX_DA_AUTHORITIES) {
                da_unlock(config);
                send(client_fd, "FULL\n", 5, MSG_NOSIGNAL);
                return 0;
            }
            slot = (int)config->consensus.num_da_sigs++;
        }
        memcpy(config->consensus.da_sigs[slot].identity_pk, peer_pk, 32);
        memcpy(config->consensus.da_sigs[slot].signature, peer_sig, 64);

        /* Classic VOTE overwrites slot: clear stale PQ fields to prevent
         * a classic vote from inheriting a previous PQ signature */
        config->consensus.da_sigs[slot].has_pq = 0;
        memset(config->consensus.da_sigs[slot].pq_signature, 0, MOOR_MLDSA_SIG_LEN);
        memset(config->consensus.da_sigs[slot].pq_pk, 0, MOOR_MLDSA_PK_LEN);

        LOG_INFO("DA: merged vote from peer DA (now %u sigs)",
                 config->consensus.num_da_sigs);
        /* Re-snapshot with peer's signature included */
        da_update_published_snapshot_unlocked(config);
        da_unlock(config);
        send(client_fd, "OK\n", 3, MSG_NOSIGNAL);
    }
    else if (strncmp(cmd_buf, "VOTE_PQ\n", 8) == 0) {
        /* Reject from non-peer: only trusted DAs may send PQ votes.
         * Without this, any relay connecting to the dir port can spam
         * VOTE_PQ and flood the log with "bad Ed25519" warnings. */
        if (!da_is_peer(client_fd, config)) {
            send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
            return 0;
        }
        /*
         * PQ vote exchange: peer DA sends hybrid signature.
         * Wire: "VOTE_PQ\n" + body_hash(32) + identity_pk(32) + ed25519_sig(64) +
         *       pq_pk(1952) + pq_sig(3309)
         */
        uint8_t *data = (uint8_t *)cmd_buf + 8;
        size_t remaining = n - 8;

        size_t pq_vote_sz = 32 + 32 + 64 + MOOR_MLDSA_PK_LEN + MOOR_MLDSA_SIG_LEN;
        uint8_t *vote_buf = malloc(pq_vote_sz);
        if (!vote_buf) { send(client_fd, "ERR\n", 4, MSG_NOSIGNAL); return -1; }

        size_t got = (remaining < pq_vote_sz) ? remaining : pq_vote_sz;
        memcpy(vote_buf, data, got);
        while (got < pq_vote_sz) {
            ssize_t r = recv(client_fd, (char *)vote_buf + got,
                             pq_vote_sz - got, 0);
            if (r <= 0) { free(vote_buf); return -1; }
            got += r;
        }

        uint8_t peer_body_hash[32], peer_pk[32], peer_sig[64];
        memcpy(peer_body_hash, vote_buf, 32);
        memcpy(peer_pk, vote_buf + 32, 32);
        memcpy(peer_sig, vote_buf + 64, 64);

        uint8_t *peer_pq_pk = vote_buf + 128;
        uint8_t *peer_pq_sig = vote_buf + 128 + MOOR_MLDSA_PK_LEN;

        da_lock(config);
        /* Verify Ed25519 signature against the body hash the SENDER
         * included — this is what they actually signed. */
        if (moor_crypto_sign_verify(peer_sig, peer_body_hash, 32, peer_pk) != 0) {
            da_unlock(config);
            LOG_WARN("DA: rejecting invalid PQ vote (bad Ed25519)");
            free(vote_buf);
            send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
            return 0;
        }
        /* Check if their body matches ours — if not, consensus diverged.
         * Rebuild to converge (same fix as VOTE path). */
        uint8_t our_body_hash[32];
        if (consensus_body_hash(our_body_hash, &config->consensus) != 0 ||
            sodium_memcmp(our_body_hash, peer_body_hash, 32) != 0) {
            da_build_consensus_unlocked(config);
            da_update_published_snapshot_unlocked(config);
            da_unlock(config);
            LOG_WARN("DA: PQ vote bodies diverged, rebuilt consensus");
            free(vote_buf);
            send(client_fd, "DIVERGED\n", 9, MSG_NOSIGNAL);
            return 0;
        }

        /* Verify peer_pk belongs to a configured DA peer AND PQ key matches */
        {
            int trusted = 0;
            /* Reject self-votes from network — DA signs locally */
            if (sodium_memcmp(config->identity_pk, peer_pk, 32) == 0) {
                da_unlock(config);
                LOG_WARN("DA: rejecting PQ self-vote received over network");
                free(vote_buf);
                send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
                return 0;
            }
            for (int p = 0; p < config->num_peers; p++) {
                if (sodium_memcmp(config->peers[p].identity_pk,
                                  peer_pk, 32) == 0) {
                    /* Also verify PQ key matches configured peer PQ key */
                    if (config->peers[p].has_pq &&
                        sodium_memcmp(config->peers[p].pq_identity_pk,
                                      peer_pq_pk, MOOR_MLDSA_PK_LEN) != 0) {
                        LOG_WARN("DA: PQ vote PQ key mismatch for peer %d", p);
                        da_unlock(config);
                        free(vote_buf);
                        send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
                        return 0;
                    }
                    trusted = 1;
                    break;
                }
            }
            if (!trusted) {
                da_unlock(config);
                LOG_WARN("DA: rejecting PQ vote from unknown/untrusted peer");
                free(vote_buf);
                send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
                return 0;
            }
        }

        /* Verify ML-DSA-65 signature against raw body */
        uint8_t *body = NULL;
        size_t body_len = 0;
        if (consensus_body_build(&body, &body_len, &config->consensus) != 0) {
            da_unlock(config);
            free(vote_buf);
            send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
            return -1;
        }

        if (moor_mldsa_verify(peer_pq_sig, MOOR_MLDSA_SIG_LEN,
                              body, body_len, peer_pq_pk) != 0) {
            da_unlock(config);
            LOG_WARN("DA: rejecting invalid PQ vote (bad ML-DSA-65)");
            free(body);
            free(vote_buf);
            send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
            return 0;
        }
        free(body);

        /* Merge: find existing slot or add new */
        int slot = -1;
        for (uint32_t i = 0; i < config->consensus.num_da_sigs; i++) {
            if (sodium_memcmp(config->consensus.da_sigs[i].identity_pk,
                             peer_pk, 32) == 0) {
                slot = (int)i;
                break;
            }
        }
        if (slot < 0) {
            if (config->consensus.num_da_sigs >= MOOR_MAX_DA_AUTHORITIES) {
                da_unlock(config);
                free(vote_buf);
                send(client_fd, "FULL\n", 5, MSG_NOSIGNAL);
                return 0;
            }
            slot = (int)config->consensus.num_da_sigs++;
        }
        memcpy(config->consensus.da_sigs[slot].identity_pk, peer_pk, 32);
        memcpy(config->consensus.da_sigs[slot].signature, peer_sig, 64);
        memcpy(config->consensus.da_sigs[slot].pq_pk, peer_pq_pk, MOOR_MLDSA_PK_LEN);
        memcpy(config->consensus.da_sigs[slot].pq_signature, peer_pq_sig,
               MOOR_MLDSA_SIG_LEN);
        config->consensus.da_sigs[slot].has_pq = 1;

        free(vote_buf);
        LOG_INFO("DA: merged PQ vote from peer DA (now %u sigs)",
                 config->consensus.num_da_sigs);
        /* Re-snapshot with peer's PQ signature included */
        da_update_published_snapshot_unlocked(config);
        da_unlock(config);
        send(client_fd, "OK\n", 3, MSG_NOSIGNAL);
    }
    else if (strncmp(cmd_buf, "SRV_REVEAL\n", 11) == 0) {
        /* Reject from non-peer: only trusted DAs may send SRV reveals */
        if (!da_is_peer(client_fd, config)) {
            LOG_WARN("SRV_REVEAL from non-peer, rejecting");
            send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
            return -1;
        }
        /* Tor-aligned: receive SRV reveal from peer DA.
         * Wire: identity_pk(32) + reveal(32) = 64 bytes */
        uint8_t *data = (uint8_t *)cmd_buf + 11;
        size_t remaining = n - 11;
        uint8_t srv_buf[64];
        size_t got = (remaining >= 64) ? 64 : remaining;
        memcpy(srv_buf, data, got);
        while (got < 64) {
            ssize_t r = recv(client_fd, (char *)srv_buf + got, 64 - got, 0);
            if (r <= 0) { send(client_fd, "ERR\n", 4, MSG_NOSIGNAL); return 0; }
            got += (size_t)r;
        }
        /* Verify identity_pk in payload matches the peer entry for this source IP.
         * Prevents a compromised peer from forging SRV reveals on behalf of
         * another DA by spoofing the identity_pk field. */
        {
            struct sockaddr_storage saddr;
            socklen_t saddrlen = sizeof(saddr);
            char src_ip[64] = "";
            if (getpeername(client_fd, (struct sockaddr *)&saddr, &saddrlen) == 0) {
                if (saddr.ss_family == AF_INET)
                    inet_ntop(AF_INET, &((struct sockaddr_in *)&saddr)->sin_addr,
                              src_ip, sizeof(src_ip));
                else if (saddr.ss_family == AF_INET6)
                    inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&saddr)->sin6_addr,
                              src_ip, sizeof(src_ip));
            }
            int id_verified = 0;
            for (int p = 0; p < config->num_peers; p++) {
                if (strcmp(config->peers[p].address, src_ip) == 0) {
                    if (sodium_memcmp(config->peers[p].identity_pk,
                                      srv_buf, 32) == 0) {
                        id_verified = 1;
                    }
                    break;
                }
            }
            if (!id_verified) {
                LOG_WARN("SRV_REVEAL: identity_pk mismatch for peer %s", src_ip);
                send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
                return -1;
            }
        }
        da_lock(config);
        moor_da_srv_reveal(config, srv_buf, 1);
        da_unlock(config);
        send(client_fd, "OK\n", 3, MSG_NOSIGNAL);
    }
    else if (strncmp(cmd_buf, "PROPAGATE\n", 10) == 0) {
        /* Reject from non-peer: only trusted DAs may propagate */
        if (!da_is_peer(client_fd, config)) {
            LOG_WARN("PROPAGATE from non-peer, rejecting");
            send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
            return -1;
        }
        /*
         * Flooded relay descriptor from a peer DA (no PoW data).
         * Validate signature only, add if new, do NOT re-propagate.
         */
        uint8_t *data = (uint8_t *)cmd_buf + 10;
        size_t remaining = n - 10;

        if (remaining < 4) return -1;
        uint32_t len = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                       ((uint32_t)data[2] << 8) | data[3];
        data += 4;
        remaining -= 4;

        if (len > 8192) {
            send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
            return -1;
        }
        uint8_t *desc_buf = malloc(len);
        if (!desc_buf) return -1;
        size_t copied = (remaining < len) ? remaining : len;
        memcpy(desc_buf, data, copied);
        while (copied < len) {
            ssize_t r = recv(client_fd, (char *)desc_buf + copied, len - copied, 0);
            if (r <= 0) { free(desc_buf); return -1; }
            copied += r;
        }

        moor_node_descriptor_t desc;
        if (moor_node_descriptor_deserialize(&desc, desc_buf, len) > 0) {
            /* Verify signature — never trust peer DA's word alone.
             * Without this, a compromised peer can inject forged relays
             * into the consensus via PROPAGATE flooding. */
            if (moor_node_verify_descriptor(&desc) != 0) {
                LOG_WARN("DA: PROPAGATE descriptor has bad signature, rejecting");
                send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
                free(desc_buf);
                return 0;
            }
            /* Reject old protocol versions */
            if (desc.protocol_version < MOOR_MIN_PROTOCOL_VERSION) {
                LOG_WARN("DA: PROPAGATE descriptor protocol version %u < %u",
                         desc.protocol_version, MOOR_MIN_PROTOCOL_VERSION);
                send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
                free(desc_buf);
                return 0;
            }
            /* Strict build_id gate (matches da_add_relay_unlocked check) */
            if (memcmp(desc.build_id, moor_build_id, MOOR_BUILD_ID_LEN) != 0) {
                char their[17];
                memcpy(their, desc.build_id, 16); their[16] = '\0';
                LOG_WARN("DA: PROPAGATE descriptor build_id '%s' mismatch", their);
                send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
                free(desc_buf);
                return 0;
            }
            da_lock(config);
            if (da_add_relay_unlocked(config, &desc) == 0) {
                LOG_INFO("DA: accepted propagated descriptor from peer");
                da_build_consensus_unlocked(config);
                /* Vote exchange removed: the sender's propagate thread
                 * votes after propagation completes.  Voting here caused
                 * overlapping cross-votes (DA2 votes back while DA1's
                 * propagate thread is still running), producing body hash
                 * mismatches and "PQ vote bodies diverged" warnings. */
                da_unlock(config);
                send(client_fd, "OK\n", 3, MSG_NOSIGNAL);
            } else {
                da_unlock(config);
                send(client_fd, "DUP\n", 4, MSG_NOSIGNAL);
            }
        } else {
            send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
        }
        free(desc_buf);
    }
    else if (strncmp(cmd_buf, "HS_PROPAGATE\n", 13) == 0) {
        /* Reject from non-peer: only trusted DAs may propagate */
        if (!da_is_peer(client_fd, config)) {
            LOG_WARN("HS_PROPAGATE from non-peer, rejecting");
            send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
            return -1;
        }
        /*
         * Flooded HS descriptor from peer DA.
         * Store if new, do NOT re-propagate.
         */
        uint8_t *data = (uint8_t *)cmd_buf + 13;
        size_t remaining = n - 13;

        uint8_t len_hdr[4];
        size_t len_got = (remaining >= 4) ? 4 : remaining;
        memcpy(len_hdr, data, len_got);
        while (len_got < 4) {
            ssize_t r = recv(client_fd, (char *)len_hdr + len_got, 4 - len_got, 0);
            if (r <= 0) return -1;
            len_got += r;
        }
        uint32_t len = ((uint32_t)len_hdr[0] << 24) | ((uint32_t)len_hdr[1] << 16) |
                       ((uint32_t)len_hdr[2] << 8) | len_hdr[3];
        data += (remaining >= 4) ? 4 : remaining;
        remaining -= (remaining >= 4) ? 4 : remaining;

        if (len > MOOR_DHT_MAX_DESC_DATA || len < 32) { /* match HS_PUBLISH limit */
            send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
            return -1;
        }

        uint8_t *hs_buf = malloc(len);
        if (!hs_buf) return -1;
        size_t copied = (remaining < len) ? remaining : len;
        memcpy(hs_buf, data, copied);
        while (copied < len) {
            ssize_t r = recv(client_fd, (char *)hs_buf + copied, len - copied, 0);
            if (r <= 0) { free(hs_buf); return -1; }
            copied += r;
        }

        uint8_t addr_hash[32];
        memcpy(addr_hash, hs_buf, 32);
        da_lock(config);
        int hs_rc = moor_da_store_hs(config, addr_hash, hs_buf, len);
        da_unlock(config);
        if (hs_rc == 0) {
            send(client_fd, "OK\n", 3, MSG_NOSIGNAL);
        } else {
            send(client_fd, "DUP\n", 4, MSG_NOSIGNAL);
        }
        free(hs_buf);
    }
    else if (strncmp(cmd_buf, "SYNC_RELAYS\n", 12) == 0) {
        /*
         * DA-to-DA relay sync: peer requests our full relay list.
         * Response: relay_count(4) + [len(2) + descriptor_bytes]...
         * Only responds to known peer DAs (verified by checking source IP).
         */
        struct sockaddr_storage peer_ss;
        socklen_t peer_len = sizeof(peer_ss);
        int trusted = 0;
        if (getpeername(client_fd, (struct sockaddr *)&peer_ss, &peer_len) == 0) {
            char peer_ip[INET6_ADDRSTRLEN];
            if (peer_ss.ss_family == AF_INET6) {
                struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&peer_ss;
                inet_ntop(AF_INET6, &a6->sin6_addr, peer_ip, sizeof(peer_ip));
            } else {
                struct sockaddr_in *a4 = (struct sockaddr_in *)&peer_ss;
                inet_ntop(AF_INET, &a4->sin_addr, peer_ip, sizeof(peer_ip));
            }
            for (int p = 0; p < config->num_peers; p++) {
                if (strcmp(config->peers[p].address, peer_ip) == 0) {
                    trusted = 1;
                    break;
                }
            }
        }
        if (!trusted) {
            LOG_WARN("DA: SYNC_RELAYS from untrusted source");
            send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
            return 0;
        }

        da_lock(config);
        uint32_t count = config->consensus.num_relays;
        uint8_t count_buf[4];
        count_buf[0] = (uint8_t)(count >> 24);
        count_buf[1] = (uint8_t)(count >> 16);
        count_buf[2] = (uint8_t)(count >> 8);
        count_buf[3] = (uint8_t)(count);
        send(client_fd, (char *)count_buf, 4, MSG_NOSIGNAL);

        uint8_t desc_wire[4096]; /* V8 descriptors with Falcon pk+sig ≈ 3500B max */
        for (uint32_t i = 0; i < count; i++) {
            int dlen = moor_node_descriptor_serialize(desc_wire + 2,
                sizeof(desc_wire) - 2, &config->consensus.relays[i]);
            if (dlen <= 0) continue;
            desc_wire[0] = (uint8_t)(dlen >> 8);
            desc_wire[1] = (uint8_t)(dlen);
            send(client_fd, (char *)desc_wire, 2 + dlen, MSG_NOSIGNAL);
        }
        da_unlock(config);
        LOG_INFO("DA: SYNC_RELAYS sent %u descriptors to peer", count);
    }
    else if (strncmp(cmd_buf, "PROBE\n", 6) == 0) {
        /*
         * Liveness probe from a DA: just reply OK.
         * DAs use this to verify relays are actually reachable.
         */
        send(client_fd, "ALIVE\n", 6, MSG_NOSIGNAL);
    }
    else {
        send(client_fd, "ERR\n", 4, MSG_NOSIGNAL);
    }

    return 0;
}

/* Internal lockless version -- caller must hold consensus_lock */
static int da_exchange_votes_unlocked(moor_da_config_t *config) {
    if (config->num_peers <= 0) return 0;

    /* Compute body hash for our signature */
    uint8_t body_hash[32];
    if (consensus_body_hash(body_hash, &config->consensus) != 0)
        return -1;

    /* Find our own signature slot */
    int our_slot = -1;
    for (uint32_t i = 0; i < config->consensus.num_da_sigs; i++) {
        if (sodium_memcmp(config->consensus.da_sigs[i].identity_pk,
                         config->identity_pk, 32) == 0) {
            our_slot = (int)i;
            break;
        }
    }
    if (our_slot < 0) return -1;

    int our_has_pq = config->consensus.da_sigs[our_slot].has_pq;

    /* Send our vote to each peer DA */
    for (int p = 0; p < config->num_peers; p++) {
        /* Skip self — compare peer identity key against ours (#208).
         * Old code compared port+bind_addr which falsely skipped all peers
         * when DA binds to 0.0.0.0 on the same port. */
        if (!sodium_is_zero(config->peers[p].identity_pk, 32) &&
            sodium_memcmp(config->peers[p].identity_pk,
                          config->identity_pk, 32) == 0) {
            continue;
        }

        int fd = moor_tcp_connect_simple(config->peers[p].address,
                                         config->peers[p].port);
        if (fd < 0) {
            LOG_WARN("DA: cannot reach peer DA at %s:%u",
                     config->peers[p].address, config->peers[p].port);
            continue;
        }
        moor_setsockopt_timeo(fd, SO_SNDTIMEO, 5);
        moor_setsockopt_timeo(fd, SO_RCVTIMEO, 5);

        /* Compute body hash — this is what our signature covers */
        uint8_t our_body_hash[32];
        consensus_body_hash(our_body_hash, &config->consensus);

        int vote_ok = 0;
        if (our_has_pq) {
            /* Send VOTE_PQ: body_hash(32) + identity_pk(32) + ed25519_sig(64) +
             * pq_pk(1952) + pq_sig(3293) */
            if (da_send_all(fd, (const uint8_t *)"VOTE_PQ\n", 8) != 0) goto vote_fail;
            size_t pq_vote_sz = 32 + 32 + 64 + MOOR_MLDSA_PK_LEN + MOOR_MLDSA_SIG_LEN;
            uint8_t *vote_data = malloc(pq_vote_sz);
            if (vote_data) {
                size_t voff = 0;
                memcpy(vote_data + voff, our_body_hash, 32); voff += 32;
                memcpy(vote_data + voff, config->identity_pk, 32); voff += 32;
                memcpy(vote_data + voff,
                       config->consensus.da_sigs[our_slot].signature, 64);
                voff += 64;
                memcpy(vote_data + voff,
                       config->consensus.da_sigs[our_slot].pq_pk,
                       MOOR_MLDSA_PK_LEN);
                voff += MOOR_MLDSA_PK_LEN;
                memcpy(vote_data + voff,
                       config->consensus.da_sigs[our_slot].pq_signature,
                       MOOR_MLDSA_SIG_LEN);
                voff += MOOR_MLDSA_SIG_LEN;
                int rc = da_send_all(fd, vote_data, voff);
                free(vote_data);
                if (rc != 0) goto vote_fail;
            }
        } else {
            /* Classic VOTE: body_hash(32) + identity_pk(32) + signature(64) */
            if (da_send_all(fd, (const uint8_t *)"VOTE\n", 5) != 0) goto vote_fail;
            uint8_t vote_data[128];
            memcpy(vote_data, our_body_hash, 32);
            memcpy(vote_data + 32, config->identity_pk, 32);
            memcpy(vote_data + 64,
                   config->consensus.da_sigs[our_slot].signature, 64);
            if (da_send_all(fd, vote_data, 128) != 0) goto vote_fail;
        }
        vote_ok = 1;
vote_fail:
        if (!vote_ok) {
            LOG_WARN("DA: vote send FAILED to peer %s:%u",
                     config->peers[p].address, config->peers[p].port);
            close(fd);
            continue;
        }

        char resp[16];
        recv(fd, resp, sizeof(resp), 0);
        close(fd);

        LOG_INFO("DA: sent %s vote to peer %s:%u",
                 our_has_pq ? "PQ" : "classic",
                 config->peers[p].address, config->peers[p].port);

        /* Tor-aligned: exchange SRV reveals after vote signature.
         * Send our commitment's reveal to the peer DA.
         * Wire: "SRV_REVEAL\n" + identity_pk(32) + reveal(32) = 64 bytes */
        for (int c = 0; c < config->num_srv_commits; c++) {
            if (sodium_memcmp(config->srv_commits[c].identity_pk,
                              config->identity_pk, 32) == 0 &&
                config->srv_commits[c].revealed) {
                int rfd = moor_tcp_connect_simple(config->peers[p].address,
                                                   config->peers[p].port);
                if (rfd >= 0) {
                    moor_setsockopt_timeo(rfd, SO_SNDTIMEO, 5);
                    da_send_all(rfd, (const uint8_t *)"SRV_REVEAL\n", 11);
                    uint8_t srv_data[64];
                    memcpy(srv_data, config->identity_pk, 32);
                    memcpy(srv_data + 32, config->srv_commits[c].reveal, 32);
                    da_send_all(rfd, srv_data, 64);
                    close(rfd);
                }
                break;
            }
        }
    }

    return 0;
}

/* Public API: acquires consensus_lock */
int moor_da_exchange_votes(moor_da_config_t *config) {
    da_lock(config);
    int ret = da_exchange_votes_unlocked(config);
    da_unlock(config);
    return ret;
}

/*
 * DA-to-DA relay sync: pull full relay list from each peer DA and merge.
 * This ensures all DAs converge to the same relay set even if they missed
 * a PUBLISH or PROPAGATE message. Runs periodically on a timer.
 *
 * Acquires consensus_lock internally. Calls _unlocked helpers to avoid
 * deadlock (sync_relays -> add_relay -> lock would deadlock a non-recursive mutex).
 */
int moor_da_sync_relays(moor_da_config_t *config) {
    if (config->num_peers <= 0) return 0;

    int total_new = 0;

    /* Fetch relay lists from peers WITHOUT holding the lock.
     * Network I/O (encrypted channel open/send/recv, 5s timeout per peer)
     * must not block CONSENSUS/PUBLISH/HS requests. */
    for (int p = 0; p < config->num_peers; p++) {
        if (sodium_is_zero(config->peers[p].identity_pk, 32)) {
            LOG_DEBUG("DA sync: skipping peer %s:%u (unknown identity)",
                      config->peers[p].address, config->peers[p].port);
            continue;
        }

        da_encrypted_channel_t ch;
        if (da_channel_open(&ch, config->peers[p].address, config->peers[p].port,
                            config->identity_pk, config->identity_sk,
                            config->peers[p].identity_pk) != 0) {
            LOG_DEBUG("DA sync: encrypted link to %s:%u failed",
                      config->peers[p].address, config->peers[p].port);
            continue;
        }

        if (da_channel_send(&ch, (const uint8_t *)"SYNC_RELAYS", 11) != 0) {
            da_channel_close(&ch);
            continue;
        }

        uint8_t *resp_data = NULL;
        ssize_t resp_len = da_channel_recv(&ch, &resp_data);
        da_channel_close(&ch);

        if (resp_len < 4 || !resp_data) {
            if (resp_data) free(resp_data);
            LOG_WARN("DA sync: bad response from %s:%u",
                     config->peers[p].address, config->peers[p].port);
            continue;
        }

        uint32_t count = ((uint32_t)resp_data[0] << 24) |
                         ((uint32_t)resp_data[1] << 16) |
                         ((uint32_t)resp_data[2] << 8) | resp_data[3];

        if (count > MOOR_MAX_RELAYS) {
            free(resp_data);
            LOG_WARN("DA sync: peer claims %u relays (too many)", count);
            continue;
        }

        /* Parse descriptors and merge under lock */
        int new_relays = 0;
        size_t off = 4;
        da_lock(config);
        for (uint32_t i = 0; i < count; i++) {
            if (off + 2 > (size_t)resp_len) break;
            uint16_t dlen = ((uint16_t)resp_data[off] << 8) | resp_data[off + 1];
            off += 2;
            if (dlen > 2048 || dlen < 64 || off + dlen > (size_t)resp_len) break;

            moor_node_descriptor_t desc;
            if (moor_node_descriptor_deserialize(&desc, resp_data + off, dlen) > 0) {
                if (moor_node_verify_descriptor(&desc) != 0) {
                    /* Diagnostic: find exact byte that differs from what our
                     * local copy would produce for the same relay */
                    int diag_match = -1;
                    for (uint32_t j = 0; j < config->consensus.num_relays; j++) {
                        if (sodium_memcmp(config->consensus.relays[j].identity_pk,
                                         desc.identity_pk, 32) == 0) {
                            diag_match = (int)j;
                            break;
                        }
                    }
                    if (diag_match >= 0) {
                        uint8_t buf_local[4096], buf_peer[4096]; /* V8 adds 897B Falcon pk to signable */
                        size_t len_local = moor_node_descriptor_signable_serialize(
                            buf_local, &config->consensus.relays[diag_match]);
                        size_t len_peer = moor_node_descriptor_signable_serialize(
                            buf_peer, &desc);
                        int first_diff = -1;
                        size_t cmp_len = len_local < len_peer ? len_local : len_peer;
                        for (size_t b = 0; b < cmp_len; b++) {
                            if (buf_local[b] != buf_peer[b]) { first_diff = (int)b; break; }
                        }
                        if (len_local != len_peer)
                            LOG_WARN("DA sync DIAG: %s signable len mismatch local=%zu peer=%zu",
                                     desc.nickname, len_local, len_peer);
                        if (first_diff >= 0)
                            LOG_WARN("DA sync DIAG: %s first diff at byte %d "
                                     "local=0x%02x peer=0x%02x (local sig valid=%d)",
                                     desc.nickname, first_diff,
                                     buf_local[first_diff], buf_peer[first_diff],
                                     moor_node_verify_descriptor(
                                         &config->consensus.relays[diag_match]) == 0);
                        else if (len_local == len_peer) {
                            int local_ok = moor_node_verify_descriptor(
                                &config->consensus.relays[diag_match]) == 0;
                            LOG_WARN("DA sync DIAG: %s signable IDENTICAL len=%zu "
                                     "sig=%02x%02x LOCAL_VERIFY=%s",
                                     desc.nickname, len_local,
                                     desc.signature[0], desc.signature[1],
                                     local_ok ? "PASS" : "FAIL");
                        }
                    } else {
                        LOG_WARN("DA sync DIAG: %s not in our consensus (new relay)",
                                 desc.nickname);
                    }
                    LOG_WARN("DA sync: rejecting descriptor %s:%u (invalid signature)",
                             desc.address, desc.or_port);
                    off += dlen;
                    continue;
                }
                /* Strict build_id gate also applies to sync-update path.
                 * da_add_relay_unlocked enforces this for new relays at :434;
                 * without this check, a relay can flip its build_id via the
                 * sync-update path and stay in consensus, defeating the gate. */
                if (memcmp(desc.build_id, moor_build_id, MOOR_BUILD_ID_LEN) != 0) {
                    char their[17], ours[17];
                    memcpy(their, desc.build_id, 16); their[16] = '\0';
                    memcpy(ours, moor_build_id, 16);  ours[16]  = '\0';
                    LOG_WARN("DA sync: rejecting %s:%u -- build_id '%s' != ours '%s'",
                             desc.address, desc.or_port, their, ours);
                    off += dlen;
                    continue;
                }
                int known = 0;
                for (uint32_t j = 0; j < config->consensus.num_relays; j++) {
                    if (sodium_memcmp(config->consensus.relays[j].identity_pk,
                                     desc.identity_pk, 32) == 0) {
                        uint64_t our_vbw = config->consensus.relays[j].verified_bandwidth;
                        uint64_t peer_vbw = desc.verified_bandwidth;
                        if (desc.published > config->consensus.relays[j].published) {
                            uint64_t fs = config->consensus.relays[j].first_seen;
                            uint8_t pf = config->consensus.relays[j].probe_failures;
                            memcpy(&config->consensus.relays[j], &desc, sizeof(desc));
                            config->consensus.relays[j].first_seen = fs;
                            config->consensus.relays[j].probe_failures = pf;
                        }
                        if (our_vbw > 0 && peer_vbw > 0) {
                            config->consensus.relays[j].verified_bandwidth =
                                (our_vbw < peer_vbw) ? our_vbw : peer_vbw;
                        } else if (our_vbw > 0) {
                            config->consensus.relays[j].verified_bandwidth = our_vbw;
                        }
                        known = 1;
                        break;
                    }
                }
                if (!known) {
                    if (da_add_relay_unlocked(config, &desc) == 0)
                        new_relays++;
                }
            }
            off += dlen;
        }
        da_unlock(config);

        free(resp_data);
        if (new_relays > 0) {
            LOG_INFO("DA sync: learned %d new relay(s) from peer %s:%u",
                     new_relays, config->peers[p].address, config->peers[p].port);
            total_new += new_relays;
        } else {
            LOG_DEBUG("DA sync: peer %s:%u had no new relays",
                      config->peers[p].address, config->peers[p].port);
        }
    }

    if (total_new > 0) {
        LOG_INFO("DA sync: total %d new relay(s), rebuilding consensus", total_new);
        da_lock(config);
        da_build_consensus_unlocked(config);
        da_unlock(config);
        moor_da_exchange_votes(config);
    }

    return total_new;
}

/*
 * Probe relays in the consensus to verify they're actually reachable.
 * Opens a TCP connection and sends "PROBE\n", expects "ALIVE\n" back.
 * Unreachable relays get their `published` timestamp zeroed so they'll
 * be evicted at the next consensus build.
 */
int moor_da_probe_relays(moor_da_config_t *config) {
    /* Snapshot relay addresses+ports under lock, then release so probing
     * (3s timeout per relay) doesn't block the entire DA. */
    da_lock(config);
    uint32_t num = config->consensus.num_relays;
    if (num == 0) { da_unlock(config); return 0; }
    if (num > MOOR_MAX_RELAYS) num = MOOR_MAX_RELAYS;

    typedef struct { char addr[64]; uint16_t port; uint64_t bandwidth;
                     uint8_t identity_pk[32]; } probe_target_t;
    probe_target_t *targets = calloc(num, sizeof(probe_target_t));
    if (!targets) { da_unlock(config); return 0; }
    for (uint32_t i = 0; i < num; i++) {
        snprintf(targets[i].addr, sizeof(targets[i].addr), "%s",
                 config->consensus.relays[i].address);
        targets[i].port = config->consensus.relays[i].or_port;
        targets[i].bandwidth = config->consensus.relays[i].bandwidth;
        memcpy(targets[i].identity_pk, config->consensus.relays[i].identity_pk, 32);
    }
    da_unlock(config);

    /* Probe without holding the lock */
    typedef struct { int alive; uint8_t failures; uint64_t measured_bw; } probe_result_t;
    probe_result_t *results = calloc(num, sizeof(probe_result_t));
    if (!results) { free(targets); return 0; }

    uint32_t probed = 0, dead_count = 0, measured = 0;
    for (uint32_t i = 0; i < num; i++) {
        int fd = moor_tcp_connect_simple(targets[i].addr, targets[i].port);
        int alive = 0;
        if (fd >= 0) {
            moor_setsockopt_timeo(fd, SO_SNDTIMEO, 3);
            moor_setsockopt_timeo(fd, SO_RCVTIMEO, 3);
            send(fd, "PROBE\n", 6, MSG_NOSIGNAL);
            char resp[16];
            ssize_t n = recv(fd, resp, sizeof(resp), 0);
            close(fd);
            if (n >= 6 && memcmp(resp, "ALIVE\n", 6) == 0)
                alive = 1;
        }
        probed++;
        results[i].alive = alive;
        if (alive) {
            moor_bw_measurement_t bw = {0};
            bw.self_reported_bw = targets[i].bandwidth;
            if (moor_bw_auth_measure(&bw, targets[i].addr, targets[i].port,
                                      256 * 1024) == 0 && bw.measured_bw > 0) {
                results[i].measured_bw = bw.measured_bw;
                measured++;
            }
        }
    }

    /* Apply results under lock */
    da_lock(config);
    for (uint32_t i = 0; i < num && i < config->consensus.num_relays; i++) {
        moor_node_descriptor_t *relay = &config->consensus.relays[i];
        /* Match by identity to handle relay list changes during probe */
        if (sodium_memcmp(relay->identity_pk, targets[i].identity_pk, 32) != 0)
            continue;
        if (results[i].alive) {
            relay->probe_failures = 0;
            if (results[i].measured_bw > 0) {
                uint64_t cap = relay->bandwidth * 2;
                if (cap < 1000000) cap = 1000000;
                relay->verified_bandwidth = results[i].measured_bw < cap ?
                    results[i].measured_bw : cap;
                LOG_DEBUG("DA bw-auth: %s:%u measured=%llu effective=%llu",
                         relay->address, relay->or_port,
                         (unsigned long long)results[i].measured_bw,
                         (unsigned long long)relay->verified_bandwidth);
            }
        } else {
            relay->probe_failures++;
            if (relay->probe_failures >= 3) {
                LOG_WARN("DA probe: relay %s:%u unreachable (%u consecutive failures), evicting",
                         relay->address, relay->or_port, relay->probe_failures);
                relay->last_registered = 0; /* triggers stale reaper */
                dead_count++;
            } else {
                LOG_INFO("DA probe: relay %s:%u missed probe (%u/3)",
                         relay->address, relay->or_port, relay->probe_failures);
            }
        }
    }
    da_unlock(config);

    free(targets);
    free(results);
    LOG_INFO("DA probe: %u/%u relays alive, %u dead, %u bw-measured",
             probed - dead_count, probed, dead_count, measured);
    return (int)dead_count;
}

int moor_da_run(moor_da_config_t *config) {
    int listen_fd = moor_listen(config->bind_addr, config->dir_port);
    if (listen_fd < 0) return -1;

    LOG_INFO("DA listening on %s:%u", config->bind_addr, config->dir_port);

    /* Simple accept loop for DA (could be event-driven in future) */
    /* For MVP, we register this with the event loop */
    return listen_fd;
}

int moor_client_fetch_consensus(moor_consensus_t *cons,
                                const char *da_address, uint16_t da_port) {
    int fd = moor_tcp_connect_simple(da_address, da_port);
    if (fd < 0) {
        LOG_WARN("consensus fetch: cannot connect to DA %s:%u",
                 da_address, da_port);
        return -1;
    }

    moor_set_socket_timeout(fd, MOOR_DA_REQUEST_TIMEOUT);
    send(fd, "CONSENSUS\n", 10, MSG_NOSIGNAL);

    /* Read length */
    uint8_t len_buf[4];
    size_t got = 0;
    while (got < 4) {
        ssize_t n = recv(fd, (char *)len_buf + got, 4 - got, 0);
        if (n <= 0) { close(fd); return -1; }
        got += n;
    }

    /* Check for error response */
    if (memcmp(len_buf, "ERR\n", 4) == 0 || memcmp(len_buf, "NONE", 4) == 0) {
        close(fd);
        return -1;
    }

    uint32_t len = ((uint32_t)len_buf[0] << 24) | ((uint32_t)len_buf[1] << 16) |
                   ((uint32_t)len_buf[2] << 8) | len_buf[3];

    if (len > 20971520) { close(fd); return -1; } /* 20 MB max for text consensus */

    uint8_t *buf = malloc(len);
    if (!buf) { close(fd); return -1; }

    got = 0;
    while (got < len) {
        ssize_t n = recv(fd, (char *)buf + got, len - got, 0);
        if (n <= 0) { free(buf); close(fd); return -1; }
        got += n;
    }
    close(fd);

    /* Transparent decompression: mirrors may send MZLB-compressed data */
    uint8_t *parse_buf = buf;
    size_t parse_len = len;
    uint8_t *decompressed = NULL;
    if (moor_consensus_is_compressed(buf, len)) {
        size_t dec_len = 0;
        if (moor_consensus_decompress(buf, len, &decompressed, &dec_len) != 0) {
            free(buf);
            return -1;
        }
        parse_buf = decompressed;
        parse_len = dec_len;
    }

    int ret = moor_consensus_deserialize(cons, parse_buf, parse_len);
    free(decompressed);
    free(buf);

    if (ret > 0) {
        /* Reject stale consensuses to prevent replay attacks */
        if (!moor_consensus_is_fresh(cons)) {
            LOG_WARN("fetched consensus is stale (valid_after=%llu, now=%llu)",
                     (unsigned long long)cons->valid_after,
                     (unsigned long long)(uint64_t)time(NULL));
            return -1;
        }
        /* Verify DA signatures against pre-configured trusted DA keys.
         * If trusted keys are available (set via moor_set_trusted_da_keys),
         * require majority verification.  Without trusted keys, fall back
         * to verifying the consensus's own signatures are internally
         * consistent (weaker but better than nothing). */
        if (g_num_trusted_da_pks >= 2) {
            if (moor_consensus_verify(cons, g_trusted_da_pks,
                                       g_num_trusted_da_pks) != 0) {
                LOG_ERROR("consensus: signature verification FAILED "
                          "(trusted DA keys)");
                return -1;
            }
        } else if (g_num_trusted_da_pks == 1) {
            uint8_t body_hash[32];
            if (consensus_body_hash(body_hash, cons) != 0) {
                LOG_ERROR("consensus: body hash computation failed");
                return -1;
            }
            /* Find the signature slot matching the trusted DA key,
             * not just index 0 which may be a different DA (CWE-290) */
            int found_trusted = 0;
            for (uint32_t si = 0; si < cons->num_da_sigs; si++) {
                if (sodium_memcmp(cons->da_sigs[si].identity_pk,
                                   g_trusted_da_pks, 32) == 0) {
                    if (moor_crypto_sign_verify(cons->da_sigs[si].signature,
                                                 body_hash, 32,
                                                 g_trusted_da_pks) != 0) {
                        LOG_ERROR("consensus: single-DA signature FAILED");
                        return -1;
                    }
                    found_trusted = 1;
                    break;
                }
            }
            if (!found_trusted) {
                LOG_ERROR("consensus: trusted DA key not found in signatures");
                return -1;
            }
        } else {
            /* No trusted keys configured -- verify internal consistency
             * (all signatures in the consensus verify against their own
             * claimed keys).  This is circular trust but catches corruption. */
            if (cons->num_da_sigs >= 1) {
                uint8_t body_hash[32];
                if (consensus_body_hash(body_hash, cons) == 0) {
                    int valid = 0;
                    for (uint32_t i = 0; i < cons->num_da_sigs; i++) {
                        if (moor_crypto_sign_verify(
                                cons->da_sigs[i].signature, body_hash, 32,
                                cons->da_sigs[i].identity_pk) == 0)
                            valid++;
                    }
                    if (valid == 0) {
                        LOG_ERROR("consensus: no valid signatures");
                        return -1;
                    }
                }
            }
            LOG_WARN("consensus: no trusted DA keys configured, "
                     "verification is weak");
        }
        /* Reject empty consensus — if all relays were reaped or the DA
         * is broken, an empty signed consensus would make the client
         * think the network has no relays and stop building circuits. */
        if (cons->num_relays == 0) {
            LOG_ERROR("consensus has 0 relays, rejecting");
            return -1;
        }
        LOG_INFO("fetched consensus: %u relays (%u DA sigs verified)",
                 cons->num_relays, cons->num_da_sigs);
        return 0;
    }
    return -1;
}

int moor_client_fetch_consensus_multi(moor_consensus_t *cons,
                                       const moor_da_entry_t *da_list,
                                       int num_das) {
    if (num_das <= 0 || !da_list) return -1;

    /* Single DA: direct call, no shuffle overhead */
    if (num_das == 1)
        return moor_client_fetch_consensus(cons, da_list[0].address, da_list[0].port);

    /* Shuffle DA order (Fisher-Yates) for load distribution */
    int order[9];
    for (int i = 0; i < num_das && i < 9; i++) order[i] = i;
    for (int i = num_das - 1; i > 0; i--) {
        uint32_t j;
        moor_crypto_random((uint8_t *)&j, sizeof(j));
        j %= (uint32_t)(i + 1);
        int tmp = order[i]; order[i] = order[j]; order[j] = tmp;
    }

    for (int i = 0; i < num_das && i < 9; i++) {
        int idx = order[i];
        LOG_INFO("trying DA %s:%u (%d/%d)",
                 da_list[idx].address, da_list[idx].port, i + 1, num_das);
        if (moor_client_fetch_consensus(cons, da_list[idx].address,
                                         da_list[idx].port) == 0)
            return 0;
    }

    /* Retry: with strict majority (e.g. 2/2 for 2 DAs), a single DA
     * signing race can cause transient verification failure.  Retry each
     * DA once more to pick up a consensus with all signatures. */
    if (num_das >= 2) {
        LOG_WARN("consensus fetch: first pass failed, retrying all %d DAs", num_das);
        for (int i = 0; i < num_das && i < 9; i++) {
            int idx = order[i];
            if (moor_client_fetch_consensus(cons, da_list[idx].address,
                                             da_list[idx].port) == 0)
                return 0;
        }
    }

    LOG_ERROR("all %d DAs unreachable", num_das);
    return -1;
}

int moor_client_fetch_consensus_fallback(moor_consensus_t *cons,
                                          const char *da_address, uint16_t da_port,
                                          const moor_fallback_t *fallbacks, int num_fallbacks) {
    /* Try DA first */
    if (moor_client_fetch_consensus(cons, da_address, da_port) == 0)
        return 0;

    LOG_WARN("DA unreachable, trying fallback directories");

    /* Shuffle fallback order for load distribution */
    int order[16];
    for (int i = 0; i < num_fallbacks && i < 16; i++) order[i] = i;
    for (int i = num_fallbacks - 1; i > 0; i--) {
        uint32_t j;
        moor_crypto_random((uint8_t *)&j, sizeof(j));
        j %= (uint32_t)(i + 1);
        int tmp = order[i]; order[i] = order[j]; order[j] = tmp;
    }

    for (int i = 0; i < num_fallbacks && i < 16; i++) {
        int idx = order[i];
        LOG_INFO("trying fallback %s:%u", fallbacks[idx].address, fallbacks[idx].dir_port);
        if (moor_client_fetch_consensus(cons, fallbacks[idx].address,
                                         fallbacks[idx].dir_port) == 0) {
            LOG_INFO("consensus fetched from fallback %s:%u",
                     fallbacks[idx].address, fallbacks[idx].dir_port);
            return 0;
        }
    }

    LOG_ERROR("all fallbacks failed");
    return -1;
}

int moor_client_fetch_hs_descriptor(moor_hs_descriptor_t *desc,
                                    const char *da_address, uint16_t da_port,
                                    const uint8_t address_hash[32],
                                    const uint8_t service_pk[32]) {
    int fd = moor_tcp_connect_simple(da_address, da_port);
    if (fd < 0) return -1;

    moor_set_socket_timeout(fd, MOOR_DA_REQUEST_TIMEOUT);
    if (send(fd, "HS_LOOKUP\n", 10, MSG_NOSIGNAL) != 10 ||
        send(fd, (char *)address_hash, 32, MSG_NOSIGNAL) != 32) {
        close(fd);
        return -1;
    }

    /* Read response */
    uint8_t len_buf[4];
    size_t got = 0;
    while (got < 4) {
        ssize_t n = recv(fd, (char *)len_buf + got, 4 - got, 0);
        if (n <= 0) { close(fd); return -1; }
        got += n;
    }

    if (memcmp(len_buf, "NONE", 4) == 0 || memcmp(len_buf, "ERR\n", 4) == 0) {
        close(fd);
        return -1;
    }

    uint32_t len = ((uint32_t)len_buf[0] << 24) | ((uint32_t)len_buf[1] << 16) |
                   ((uint32_t)len_buf[2] << 8) | len_buf[3];

    /* Cap matches MOOR_DHT_MAX_DESC_DATA (32 KB) to accept PQ client-auth
     * descriptors with up to 16 ML-KEM-sealed entries. */
    if (len > MOOR_DHT_MAX_DESC_DATA || len < 48) { close(fd); return -1; }

    uint8_t *buf = malloc(len);
    if (!buf) { close(fd); return -1; }

    got = 0;
    while (got < len) {
        ssize_t n = recv(fd, (char *)buf + got, len - got, 0);
        if (n <= 0) { free(buf); close(fd); return -1; }
        got += n;
    }
    close(fd);

    /*
     * Encrypted wire format from DA (v2):
     *   address_hash(32) + ver(1=0x02) + nonce(12) + ciphertext(plaintext + 16 MAC)
     * Derive desc_key = BLAKE2b("moor-desc" || service_pk || time_period)
     */
    if (len < 32 + 1 + 12 + 16 || buf[32] != 0x02) { free(buf); return -1; }

    const uint8_t *nonce12 = buf + 33;
    size_t ct_len = len - (32 + 1 + 12);

    uint8_t *plaintext = malloc(ct_len);
    if (!plaintext) { free(buf); return -1; }

    /*
     * Try current time period, then +-1 to handle clock skew and
     * period boundaries. Descriptor was encrypted with the service's
     * time_period, which may differ by one epoch from the client's.
     */
    uint64_t base_tp = (uint64_t)time(NULL) / MOOR_TIME_PERIOD_SECS;
    int64_t tp_offsets[] = { 0, -1, 1 };
    int decrypted = 0;
    size_t pt_len = 0;

    for (int ti = 0; ti < 3; ti++) {
        uint64_t time_period = base_tp + (uint64_t)tp_offsets[ti];
        uint8_t desc_key_input[49];
        memcpy(desc_key_input, "moor-desc", 9);
        memcpy(desc_key_input + 9, service_pk, 32);
        for (int i = 0; i < 8; i++)
            desc_key_input[41 + i] = (uint8_t)(time_period >> (i * 8));
        uint8_t desc_key[32];
        moor_crypto_hash(desc_key, desc_key_input, 49);

        if (moor_crypto_aead_decrypt_n12(plaintext, &pt_len,
                                          buf + 45, ct_len,
                                          buf, 32, desc_key, nonce12) == 0) {
            decrypted = 1;
            sodium_memzero(desc_key, 32);
            break;
        }
        sodium_memzero(desc_key, 32);
    }

    if (!decrypted) {
        LOG_ERROR("HS descriptor decryption failed (tried 3 time periods)");
        sodium_memzero(plaintext, ct_len);
        free(plaintext);
        sodium_memzero(buf, len);
        free(buf);
        return -1;
    }
    sodium_memzero(buf, len);
    free(buf);

    int ret = moor_hs_descriptor_deserialize(desc, plaintext, pt_len);
    sodium_memzero(plaintext, ct_len);
    free(plaintext);
    if (ret <= 0) return -1;

    /* Anti-replay: reject descriptors with stale revision counters.
     * Cache last-seen revision per address_hash. */
    static struct { uint8_t hash[32]; uint64_t revision; } rev_cache[64];
    static int rev_cache_count = 0;
    for (int i = 0; i < rev_cache_count; i++) {
        if (sodium_memcmp(rev_cache[i].hash, desc->address_hash, 32) == 0) {
            if (desc->revision < rev_cache[i].revision) {
                LOG_WARN("HS descriptor replay: revision %llu < cached %llu",
                         (unsigned long long)desc->revision,
                         (unsigned long long)rev_cache[i].revision);
                return -1;
            }
            rev_cache[i].revision = desc->revision;
            return 0;
        }
    }
    /* New HS — add to cache */
    if (rev_cache_count < 64) {
        memcpy(rev_cache[rev_cache_count].hash, desc->address_hash, 32);
        rev_cache[rev_cache_count].revision = desc->revision;
        rev_cache_count++;
    }
    return 0;
}

/*
 * HS descriptor wire format:
 *   address_hash(32) + service_pk(32) + onion_pk(32) + blinded_pk(32)
 *   + num_intro(4) + [node_id(32) + address(64) + or_port(2)] * num_intro
 *   + signature(64) + published(8)
 */
int moor_hs_descriptor_serialize(uint8_t *out, size_t out_len,
                                 const moor_hs_descriptor_t *desc) {
    size_t needed = 32 + 32 + 32 + 32 + 4 + desc->num_intro_points * 98 + 64 + 8
                   + 8 /* revision counter */
                   + 1 /* auth_type */
                   + 32 + 1 /* pow_seed + pow_difficulty */
                   + 1 + (desc->kem_available ? 1184 : 0) /* PQ KEM pk */
                   + 1 + (desc->falcon_available ? 897 : 0) /* Falcon-512 pk */;
    if (desc->auth_type == 1 && desc->num_auth_entries > 0)
        needed += 1 + (size_t)desc->num_auth_entries * 80;
    if (out_len < needed) return -1;

    size_t off = 0;
    memcpy(out + off, desc->address_hash, 32); off += 32;
    memcpy(out + off, desc->service_pk, 32); off += 32;
    memcpy(out + off, desc->onion_pk, 32); off += 32;
    memcpy(out + off, desc->blinded_pk, 32); off += 32;
    out[off++] = (uint8_t)(desc->num_intro_points >> 24);
    out[off++] = (uint8_t)(desc->num_intro_points >> 16);
    out[off++] = (uint8_t)(desc->num_intro_points >> 8);
    out[off++] = (uint8_t)(desc->num_intro_points);

    for (uint32_t i = 0; i < desc->num_intro_points && i < MOOR_MAX_INTRO_POINTS; i++) {
        memcpy(out + off, desc->intro_points[i].node_id, 32); off += 32;
        memcpy(out + off, desc->intro_points[i].address, 64); off += 64;
        out[off++] = (uint8_t)(desc->intro_points[i].or_port >> 8);
        out[off++] = (uint8_t)(desc->intro_points[i].or_port);
    }

    memcpy(out + off, desc->signature, 64); off += 64;
    /* Encode published timestamp in big-endian (portable) */
    out[off++] = (uint8_t)(desc->published >> 56);
    out[off++] = (uint8_t)(desc->published >> 48);
    out[off++] = (uint8_t)(desc->published >> 40);
    out[off++] = (uint8_t)(desc->published >> 32);
    out[off++] = (uint8_t)(desc->published >> 24);
    out[off++] = (uint8_t)(desc->published >> 16);
    out[off++] = (uint8_t)(desc->published >> 8);
    out[off++] = (uint8_t)(desc->published);

    /* Revision counter (big-endian) -- anti-replay */
    out[off++] = (uint8_t)(desc->revision >> 56);
    out[off++] = (uint8_t)(desc->revision >> 48);
    out[off++] = (uint8_t)(desc->revision >> 40);
    out[off++] = (uint8_t)(desc->revision >> 32);
    out[off++] = (uint8_t)(desc->revision >> 24);
    out[off++] = (uint8_t)(desc->revision >> 16);
    out[off++] = (uint8_t)(desc->revision >> 8);
    out[off++] = (uint8_t)(desc->revision);

    /* Auth section: auth_type(1) + [num_entries(1) + entries[]] */
    out[off++] = desc->auth_type;
    if (desc->auth_type == 1 && desc->num_auth_entries > 0) {
        out[off++] = desc->num_auth_entries;
        for (int i = 0; i < desc->num_auth_entries && i < 16; i++) {
            memcpy(out + off, desc->auth_entries[i], 80);
            off += 80;
        }
    }

    /* PoW section: pow_seed(32) + pow_difficulty(1) */
    memcpy(out + off, desc->pow_seed, 32); off += 32;
    out[off++] = desc->pow_difficulty;

    /* PQ e2e KEM public key: flag(1) + [kem_pk(1184)] */
    out[off++] = (uint8_t)desc->kem_available;
    if (desc->kem_available) {
        memcpy(out + off, desc->kem_pk, 1184);
        off += 1184;
    }

    /* PQ HS identity: flag(1) + [falcon_pk(897)] */
    out[off++] = (uint8_t)desc->falcon_available;
    if (desc->falcon_available) {
        memcpy(out + off, desc->falcon_pk, 897);
        off += 897;
    }

    return (int)off;
}

int moor_hs_descriptor_deserialize(moor_hs_descriptor_t *desc,
                                   const uint8_t *data, size_t data_len) {
    if (data_len < 132) return -1; /* 32+32+32+32+4 minimum */
    memset(desc, 0, sizeof(*desc));
    size_t off = 0;
    memcpy(desc->address_hash, data + off, 32); off += 32;
    memcpy(desc->service_pk, data + off, 32); off += 32;
    memcpy(desc->onion_pk, data + off, 32); off += 32;
    memcpy(desc->blinded_pk, data + off, 32); off += 32;
    desc->num_intro_points = ((uint32_t)data[off] << 24) |
                              ((uint32_t)data[off+1] << 16) |
                              ((uint32_t)data[off+2] << 8) | data[off+3];
    off += 4;

    if (desc->num_intro_points > MOOR_MAX_INTRO_POINTS) {
        LOG_WARN("descriptor has invalid num_intro_points=%u, rejecting",
                 desc->num_intro_points);
        return -1;
    }

    for (uint32_t i = 0; i < desc->num_intro_points; i++) {
        if (off + 98 > data_len) return -1;
        memcpy(desc->intro_points[i].node_id, data + off, 32); off += 32;
        memcpy(desc->intro_points[i].address, data + off, 64); off += 64;
        desc->intro_points[i].address[63] = '\0'; /* NUL-terminate */
        desc->intro_points[i].or_port = ((uint16_t)data[off] << 8) | data[off+1];
        off += 2;
    }

    if (off + 72 > data_len) return -1;
    memcpy(desc->signature, data + off, 64); off += 64;
    /* Decode published timestamp from big-endian */
    desc->published = ((uint64_t)data[off] << 56) |
                      ((uint64_t)data[off+1] << 48) |
                      ((uint64_t)data[off+2] << 40) |
                      ((uint64_t)data[off+3] << 32) |
                      ((uint64_t)data[off+4] << 24) |
                      ((uint64_t)data[off+5] << 16) |
                      ((uint64_t)data[off+6] << 8) |
                      (uint64_t)data[off+7];
    off += 8;

    /* Revision counter (anti-replay) */
    if (off + 8 <= data_len) {
        desc->revision = ((uint64_t)data[off] << 56) |
                          ((uint64_t)data[off+1] << 48) |
                          ((uint64_t)data[off+2] << 40) |
                          ((uint64_t)data[off+3] << 32) |
                          ((uint64_t)data[off+4] << 24) |
                          ((uint64_t)data[off+5] << 16) |
                          ((uint64_t)data[off+6] << 8) |
                          (uint64_t)data[off+7];
        off += 8;
    }

    /* Auth section (optional) */
    if (off < data_len) {
        desc->auth_type = data[off++];
        if (desc->auth_type == 1 && off < data_len) {
            desc->num_auth_entries = data[off++];
            if (desc->num_auth_entries > 16) {
                LOG_WARN("descriptor has invalid num_auth_entries=%u, rejecting",
                         desc->num_auth_entries);
                return -1;
            }
            /* Reject rather than silently accept a partial auth list: a
             * truncated descriptor that claims N entries but only contains K<N
             * would otherwise leave the remaining slots uninitialized, letting
             * a client appear authorized or failing auth randomly. */
            for (int i = 0; i < desc->num_auth_entries; i++) {
                if (off + 80 > data_len) {
                    LOG_WARN("descriptor truncated in auth section (need %d entries, have %d)",
                             desc->num_auth_entries, i);
                    return -1;
                }
                memcpy(desc->auth_entries[i], data + off, 80);
                off += 80;
            }
        }
    }

    /* PoW section (optional): pow_seed(32) + pow_difficulty(1) */
    if (off + 33 <= data_len) {
        memcpy(desc->pow_seed, data + off, 32); off += 32;
        desc->pow_difficulty = data[off++];
    }

    /* PQ e2e KEM public key (optional): flag(1) + [kem_pk(1184)] */
    if (off < data_len) {
        desc->kem_available = data[off++];
        if (desc->kem_available && off + 1184 <= data_len) {
            memcpy(desc->kem_pk, data + off, 1184);
            off += 1184;
        } else if (desc->kem_available) {
            desc->kem_available = 0; /* truncated */
        }
    }

    /* PQ HS identity Falcon-512 pk (optional): flag(1) + [falcon_pk(897)] */
    if (off < data_len) {
        desc->falcon_available = data[off++];
        if (desc->falcon_available && off + 897 <= data_len) {
            memcpy(desc->falcon_pk, data + off, 897);
            off += 897;
        } else if (desc->falcon_available) {
            desc->falcon_available = 0; /* truncated */
        }
    }

    return (int)off;
}

/* ---- Consensus caching ---- */

int moor_consensus_cache_save(const moor_consensus_t *cons,
                               const char *data_dir) {
    char path[512];
    snprintf(path, sizeof(path), "%s/cached-consensus", data_dir);

    size_t buf_sz = moor_consensus_wire_size(cons);
    if (buf_sz < 1024) buf_sz = 1024;
    uint8_t *buf = malloc(buf_sz);
    if (!buf) return -1;
    int len = moor_consensus_serialize(buf, buf_sz, cons);
    if (len <= 0) { free(buf); return -1; }

    FILE *f = fopen(path, "wb");
    if (!f) { free(buf); return -1; }

    if (fwrite(buf, 1, (size_t)len, f) != (size_t)len) {
        fclose(f);
        free(buf);
        return -1;
    }
    fflush(f);
    fclose(f);
    free(buf);

    LOG_INFO("consensus cached to %s (%d bytes)", path, len);
    return 0;
}

int moor_consensus_cache_load(moor_consensus_t *cons,
                               const char *data_dir) {
    char path[512];
    snprintf(path, sizeof(path), "%s/cached-consensus", data_dir);

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long file_len = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_len <= 0 || file_len > 4194304) {
        fclose(f);
        return -1;
    }

    uint8_t *buf = malloc((size_t)file_len);
    if (!buf) { fclose(f); return -1; }

    if (fread(buf, 1, (size_t)file_len, f) != (size_t)file_len) {
        free(buf);
        fclose(f);
        return -1;
    }
    fclose(f);

    int ret = moor_consensus_deserialize(cons, buf, (size_t)file_len);
    free(buf);

    if (ret <= 0) return -1;

    LOG_INFO("consensus loaded from cache (%ld bytes)", file_len);
    return 0;
}

int moor_consensus_is_fresh(const moor_consensus_t *cons) {
    uint64_t now = (uint64_t)time(NULL);
    /* Allow 5s clock skew between DA and relay (#184) */
    uint64_t skew = 5;
    uint64_t lower = (cons->valid_after > skew) ? cons->valid_after - skew : 0;
    /* Use fresh_until (1 consensus interval, ~1h) instead of valid_until
     * (3 intervals, ~3h) to tighten the replay window.  Fall back to
     * valid_until if fresh_until is not set (old consensus format). */
    uint64_t upper = cons->fresh_until > 0 ? cons->fresh_until : cons->valid_until;
    return (now >= lower && now < upper) ? 1 : 0;
}

/* Like is_fresh but uses valid_until (3 consensus intervals, ~3h) instead
 * of fresh_until.  Use this for "can I still route traffic?" decisions —
 * circuit building, cached-consensus acceptance — so the network keeps
 * working during DA restarts.  Reserve is_fresh for "should I fetch a
 * new consensus?" decisions. */
int moor_consensus_is_valid(const moor_consensus_t *cons) {
    uint64_t now = (uint64_t)time(NULL);
    uint64_t skew = 5;
    uint64_t lower = (cons->valid_after > skew) ? cons->valid_after - skew : 0;
    return (now >= lower && now < cons->valid_until) ? 1 : 0;
}

/* --- DA Signing Key Cert Operations (Phase 8) --- */

int moor_da_generate_signing_cert(moor_da_config_t *config) {
    /* Generate online signing keypair */
    moor_crypto_sign_keygen(config->signing_pk, config->signing_sk);

    /* Build cert: sign (signing_pk || valid_from || valid_until) with identity_sk */
    config->cert.valid_from = (uint64_t)time(NULL);
    config->cert.valid_until = config->cert.valid_from + MOOR_DA_CERT_LIFETIME_SEC;
    memcpy(config->cert.signing_pk, config->signing_pk, 32);
    memcpy(config->cert.identity_pk, config->identity_pk, 32);

    uint8_t to_sign[48]; /* signing_pk(32) + valid_from(8) + valid_until(8) */
    memcpy(to_sign, config->signing_pk, 32);
    for (int i = 7; i >= 0; i--) to_sign[32 + (7 - i)] = (uint8_t)(config->cert.valid_from >> (i * 8));
    for (int i = 7; i >= 0; i--) to_sign[40 + (7 - i)] = (uint8_t)(config->cert.valid_until >> (i * 8));

    if (moor_crypto_sign(config->cert.signature, to_sign, 48, config->identity_sk) != 0)
        return -1;

    LOG_INFO("DA: generated signing cert (valid %llu days)",
             (unsigned long long)(MOOR_DA_CERT_LIFETIME_SEC / 86400));
    return 0;
}

int moor_da_verify_signing_cert(const moor_da_signing_cert_t *cert) {
    if (!cert) return -1;

    /* Check expiry */
    uint64_t now = (uint64_t)time(NULL);
    if (now < cert->valid_from || now >= cert->valid_until)
        return -1;

    /* Verify signature: identity_pk signs (signing_pk || valid_from || valid_until) */
    uint8_t to_verify[48];
    memcpy(to_verify, cert->signing_pk, 32);
    for (int i = 7; i >= 0; i--) to_verify[32 + (7 - i)] = (uint8_t)(cert->valid_from >> (i * 8));
    for (int i = 7; i >= 0; i--) to_verify[40 + (7 - i)] = (uint8_t)(cert->valid_until >> (i * 8));

    return moor_crypto_sign_verify(cert->signature, to_verify, 48, cert->identity_pk);
}

int moor_da_rotate_signing_key(moor_da_config_t *config) {
    /* Wipe old signing key */
    moor_crypto_wipe(config->signing_sk, 64);
    return moor_da_generate_signing_cert(config);
}

/* --- Consensus Diff (Phase 8) --- */
/* Static relay pointer for qsort comparator (no context arg in C qsort) */
static const moor_node_descriptor_t *qsort_relays_ptr;
static int diff_sort_cmp_fn(const void *a, const void *b) {
    uint32_t ia = *(const uint32_t *)a, ib = *(const uint32_t *)b;
    return memcmp(qsort_relays_ptr[ia].identity_pk,
                  qsort_relays_ptr[ib].identity_pk, 32);
}

int moor_da_build_consensus_diff(const moor_consensus_t *old_cons,
                                  const moor_consensus_t *new_cons,
                                  uint8_t *buf, size_t buf_len) {
    if (!old_cons || !new_cons || !buf) return -1;

    size_t off = 0;

    /* Header: magic(4) + from_valid_after(8) + to_valid_after(8) + num_entries(4) = 24 */
    if (buf_len < 24) return -1;

    /* Write magic */
    buf[off++] = (uint8_t)(MOOR_CONSENSUS_DIFF_MAGIC >> 24);
    buf[off++] = (uint8_t)(MOOR_CONSENSUS_DIFF_MAGIC >> 16);
    buf[off++] = (uint8_t)(MOOR_CONSENSUS_DIFF_MAGIC >> 8);
    buf[off++] = (uint8_t)(MOOR_CONSENSUS_DIFF_MAGIC);

    /* from/to timestamps */
    for (int i = 7; i >= 0; i--) buf[off++] = (uint8_t)(old_cons->valid_after >> (i * 8));
    for (int i = 7; i >= 0; i--) buf[off++] = (uint8_t)(new_cons->valid_after >> (i * 8));

    /* Reserve space for num_entries */
    size_t num_entries_off = off;
    off += 4;

    uint32_t num_entries = 0;

    /* O(n log n) sort+merge approach instead of O(n²) nested loops.
     * Build sorted index arrays, then single merge pass. */
    uint32_t old_n = old_cons->num_relays;
    uint32_t new_n = new_cons->num_relays;

    /* Build sorted index arrays by identity_pk */
    uint32_t *old_idx = malloc(old_n * sizeof(uint32_t));
    uint32_t *new_idx = malloc(new_n * sizeof(uint32_t));
    if (!old_idx || !new_idx) { free(old_idx); free(new_idx); return -1; }
    for (uint32_t i = 0; i < old_n; i++) old_idx[i] = i;
    for (uint32_t i = 0; i < new_n; i++) new_idx[i] = i;

    /* Sort both index arrays by identity_pk using a static helper */
    qsort_relays_ptr = old_cons->relays;
    qsort(old_idx, old_n, sizeof(uint32_t), diff_sort_cmp_fn);
    qsort_relays_ptr = new_cons->relays;
    qsort(new_idx, new_n, sizeof(uint32_t), diff_sort_cmp_fn);

    /* Merge pass: single scan of both sorted arrays */
    uint32_t oi = 0, ni = 0;
    while (oi < old_n && ni < new_n) {
        int cmp = memcmp(old_cons->relays[old_idx[oi]].identity_pk,
                        new_cons->relays[new_idx[ni]].identity_pk, 32);
        if (cmp < 0) {
            /* Old relay not in new → REMOVE */
            if (off + 33 > buf_len) { free(old_idx); free(new_idx); return -1; }
            buf[off++] = MOOR_DIFF_OP_REMOVE;
            memcpy(buf + off, old_cons->relays[old_idx[oi]].identity_pk, 32); off += 32;
            num_entries++;
            oi++;
        } else if (cmp > 0) {
            /* New relay not in old → ADD */
            if (off + 111 > buf_len) { free(old_idx); free(new_idx); return -1; }
            buf[off++] = MOOR_DIFF_OP_ADD;
            memcpy(buf + off, new_cons->relays[new_idx[ni]].identity_pk, 32); off += 32;
            buf[off++] = (uint8_t)(new_cons->relays[new_idx[ni]].flags >> 24);
            buf[off++] = (uint8_t)(new_cons->relays[new_idx[ni]].flags >> 16);
            buf[off++] = (uint8_t)(new_cons->relays[new_idx[ni]].flags >> 8);
            buf[off++] = (uint8_t)(new_cons->relays[new_idx[ni]].flags);
            for (int k = 7; k >= 0; k--)
                buf[off++] = (uint8_t)(new_cons->relays[new_idx[ni]].bandwidth >> (k * 8));
            memcpy(buf + off, new_cons->relays[new_idx[ni]].address, 64); off += 64;
            buf[off++] = (uint8_t)(new_cons->relays[new_idx[ni]].or_port >> 8);
            buf[off++] = (uint8_t)(new_cons->relays[new_idx[ni]].or_port);
            num_entries++;
            ni++;
        } else {
            /* Same relay -- check for changes */
            uint32_t o = old_idx[oi], n = new_idx[ni];
            if (old_cons->relays[o].flags != new_cons->relays[n].flags ||
                old_cons->relays[o].bandwidth != new_cons->relays[n].bandwidth) {
                if (off + 45 > buf_len) { free(old_idx); free(new_idx); return -1; }
                buf[off++] = MOOR_DIFF_OP_CHANGE;
                memcpy(buf + off, new_cons->relays[n].identity_pk, 32); off += 32;
                buf[off++] = (uint8_t)(new_cons->relays[n].flags >> 24);
                buf[off++] = (uint8_t)(new_cons->relays[n].flags >> 16);
                buf[off++] = (uint8_t)(new_cons->relays[n].flags >> 8);
                buf[off++] = (uint8_t)(new_cons->relays[n].flags);
                for (int k = 7; k >= 0; k--)
                    buf[off++] = (uint8_t)(new_cons->relays[n].bandwidth >> (k * 8));
                num_entries++;
            }
            oi++;
            ni++;
        }
    }
    /* Remaining old → REMOVE */
    while (oi < old_n) {
        if (off + 33 > buf_len) { free(old_idx); free(new_idx); return -1; }
        buf[off++] = MOOR_DIFF_OP_REMOVE;
        memcpy(buf + off, old_cons->relays[old_idx[oi]].identity_pk, 32); off += 32;
        num_entries++;
        oi++;
    }
    /* Remaining new → ADD */
    while (ni < new_n) {
        if (off + 111 > buf_len) { free(old_idx); free(new_idx); return -1; }
        buf[off++] = MOOR_DIFF_OP_ADD;
        memcpy(buf + off, new_cons->relays[new_idx[ni]].identity_pk, 32); off += 32;
        buf[off++] = (uint8_t)(new_cons->relays[new_idx[ni]].flags >> 24);
        buf[off++] = (uint8_t)(new_cons->relays[new_idx[ni]].flags >> 16);
        buf[off++] = (uint8_t)(new_cons->relays[new_idx[ni]].flags >> 8);
        buf[off++] = (uint8_t)(new_cons->relays[new_idx[ni]].flags);
        for (int k = 7; k >= 0; k--)
            buf[off++] = (uint8_t)(new_cons->relays[new_idx[ni]].bandwidth >> (k * 8));
        memcpy(buf + off, new_cons->relays[new_idx[ni]].address, 64); off += 64;
        buf[off++] = (uint8_t)(new_cons->relays[new_idx[ni]].or_port >> 8);
        buf[off++] = (uint8_t)(new_cons->relays[new_idx[ni]].or_port);
        num_entries++;
        ni++;
    }
    free(old_idx);
    free(new_idx);

    /* Write num_entries */
    buf[num_entries_off]     = (uint8_t)(num_entries >> 24);
    buf[num_entries_off + 1] = (uint8_t)(num_entries >> 16);
    buf[num_entries_off + 2] = (uint8_t)(num_entries >> 8);
    buf[num_entries_off + 3] = (uint8_t)(num_entries);

    /* Append BLAKE2b-256 hash of new consensus body for integrity check */
    if (off + 32 <= buf_len) {
        uint8_t body_hash[32];
        if (consensus_body_hash(body_hash, new_cons) == 0) {
            memcpy(buf + off, body_hash, 32);
            off += 32;
        }
    }

    return (int)off;
}

int moor_client_apply_consensus_diff(moor_consensus_t *cons,
                                      const uint8_t *diff, size_t diff_len) {
    if (!cons || !diff || diff_len < 24) return -1;

    size_t off = 0;

    /* Verify magic */
    uint32_t magic = ((uint32_t)diff[0] << 24) | ((uint32_t)diff[1] << 16) |
                     ((uint32_t)diff[2] << 8) | diff[3];
    if (magic != MOOR_CONSENSUS_DIFF_MAGIC) return -1;
    off += 4;

    /* Read from_valid_after and verify it matches current consensus */
    uint64_t from_va = 0;
    for (int i = 7; i >= 0; i--) from_va |= (uint64_t)diff[off++] << (i * 8);
    if (from_va != cons->valid_after) return -1;

    /* Read to_valid_after */
    uint64_t to_va = 0;
    for (int i = 7; i >= 0; i--) to_va |= (uint64_t)diff[off++] << (i * 8);

    /* Read num_entries */
    uint32_t num_entries = ((uint32_t)diff[off] << 24) | ((uint32_t)diff[off+1] << 16) |
                           ((uint32_t)diff[off+2] << 8) | diff[off+3];
    off += 4;

    for (uint32_t e = 0; e < num_entries; e++) {
        if (off >= diff_len) return -1;
        uint8_t op = diff[off++];

        if (op == MOOR_DIFF_OP_REMOVE) {
            if (off + 32 > diff_len) return -1;
            const uint8_t *pk = diff + off; off += 32;
            /* Find and remove relay */
            for (uint32_t i = 0; i < cons->num_relays; i++) {
                if (sodium_memcmp(cons->relays[i].identity_pk, pk, 32) == 0) {
                    cons->relays[i] = cons->relays[cons->num_relays - 1];
                    cons->num_relays--;
                    break;
                }
            }
        } else if (op == MOOR_DIFF_OP_CHANGE) {
            if (off + 44 > diff_len) return -1;
            const uint8_t *pk = diff + off; off += 32;
            uint32_t flags = ((uint32_t)diff[off] << 24) | ((uint32_t)diff[off+1] << 16) |
                             ((uint32_t)diff[off+2] << 8) | diff[off+3]; off += 4;
            uint64_t bw = 0;
            for (int k = 7; k >= 0; k--) bw |= (uint64_t)diff[off++] << (k * 8);
            /* Find and update relay */
            for (uint32_t i = 0; i < cons->num_relays; i++) {
                if (sodium_memcmp(cons->relays[i].identity_pk, pk, 32) == 0) {
                    cons->relays[i].flags = flags;
                    cons->relays[i].bandwidth = bw;
                    break;
                }
            }
        } else if (op == MOOR_DIFF_OP_ADD) {
            if (off + 110 > diff_len) return -1;
            if (cons->num_relays >= MOOR_MAX_RELAYS) { off += 110; continue; }
            /* Grow relay array if needed */
            if (cons->num_relays >= cons->relay_capacity) {
                uint32_t new_cap = cons->relay_capacity * 2;
                if (new_cap > MOOR_MAX_RELAYS) new_cap = MOOR_MAX_RELAYS;
                if (new_cap < 256) new_cap = 256;
                moor_node_descriptor_t *grown = realloc(cons->relays,
                    new_cap * sizeof(moor_node_descriptor_t));
                if (!grown) return -1;
                cons->relays = grown;
                cons->relay_capacity = new_cap;
            }
            moor_node_descriptor_t *d = &cons->relays[cons->num_relays];
            memset(d, 0, sizeof(*d));
            memcpy(d->identity_pk, diff + off, 32); off += 32;
            d->flags = ((uint32_t)diff[off] << 24) | ((uint32_t)diff[off+1] << 16) |
                       ((uint32_t)diff[off+2] << 8) | diff[off+3]; off += 4;
            d->bandwidth = 0;
            for (int k = 7; k >= 0; k--) d->bandwidth |= (uint64_t)diff[off++] << (k * 8);
            memcpy(d->address, diff + off, 64); off += 64;
            d->address[63] = '\0';
            d->or_port = ((uint16_t)diff[off] << 8) | diff[off+1]; off += 2;
            cons->num_relays++;
        } else {
            return -1; /* unknown op */
        }
    }

    cons->valid_after = to_va;

    /* Verify integrity hash if present (last 32 bytes of diff).
     * The diff only carries a subset of relay fields, so the hash may
     * not match when the new consensus has fields that the diff doesn't
     * carry (e.g., onion_pk, signature).  Log a warning for monitoring
     * but do not reject — the consensus signatures are the authoritative
     * integrity check. */
    if (off + 32 <= diff_len) {
        uint8_t expected_hash[32];
        memcpy(expected_hash, diff + off, 32);
        uint8_t actual_hash[32];
        if (consensus_body_hash(actual_hash, cons) == 0 &&
            sodium_memcmp(expected_hash, actual_hash, 32) != 0) {
            LOG_WARN("consensus diff integrity hash mismatch (partial relay data)");
        }
    }

    return 0;
}

int moor_client_fetch_microdesc_consensus(moor_microdesc_consensus_t *mc,
                                           const char *da_address,
                                           uint16_t da_port) {
    int fd = moor_tcp_connect_simple(da_address, da_port);
    if (fd < 0) return -1;

    moor_set_socket_timeout(fd, MOOR_DA_REQUEST_TIMEOUT);
    send(fd, "MICRODESC\n", 10, MSG_NOSIGNAL);

    /* Read length */
    uint8_t len_buf[4];
    size_t got = 0;
    while (got < 4) {
        ssize_t n = recv(fd, (char *)len_buf + got, 4 - got, 0);
        if (n <= 0) { close(fd); return -1; }
        got += n;
    }

    if (memcmp(len_buf, "ERR\n", 4) == 0 || memcmp(len_buf, "NONE", 4) == 0) {
        close(fd);
        return -1;
    }

    uint32_t len = ((uint32_t)len_buf[0] << 24) | ((uint32_t)len_buf[1] << 16) |
                   ((uint32_t)len_buf[2] << 8) | len_buf[3];

    if (len > 2097152) { close(fd); return -1; } /* 2 MB max for microdesc */

    uint8_t *buf = malloc(len);
    if (!buf) { close(fd); return -1; }

    got = 0;
    while (got < len) {
        ssize_t n = recv(fd, (char *)buf + got, len - got, 0);
        if (n <= 0) { free(buf); close(fd); return -1; }
        got += n;
    }
    close(fd);

    int ret = moor_microdesc_consensus_deserialize(mc, buf, len);
    free(buf);

    if (ret > 0) {
        LOG_INFO("fetched microdesc consensus: %u relays (%u bytes)",
                 mc->num_relays, len);
        return 0;
    }
    return -1;
}

/* ================================================================
 * SRV commit-reveal protocol
 * ================================================================ */
int moor_da_srv_generate_commit(moor_da_config_t *config) {
    if (!config) return -1;

    /* Generate random reveal */
    moor_srv_commitment_t *my = NULL;
    for (int i = 0; i < config->num_srv_commits; i++) {
        if (sodium_memcmp(config->srv_commits[i].identity_pk,
                          config->identity_pk, 32) == 0) {
            my = &config->srv_commits[i];
            break;
        }
    }
    if (!my) {
        if (config->num_srv_commits >= MOOR_MAX_DA_AUTHORITIES)
            return -1;
        my = &config->srv_commits[config->num_srv_commits++];
        memcpy(my->identity_pk, config->identity_pk, 32);
    }

    moor_crypto_random(my->reveal, 32);
    moor_crypto_hash(my->commit, my->reveal, 32);
    my->revealed = 1; /* we know our own reveal */

    LOG_INFO("SRV: generated commit for this DA");
    return 0;
}

int moor_da_srv_reveal(moor_da_config_t *config,
                        const uint8_t *reveals, int num_reveals) {
    if (!config || !reveals) return -1;

    /* Each reveal is: identity_pk(32) + reveal(32) = 64 bytes */
    for (int r = 0; r < num_reveals; r++) {
        const uint8_t *pk = reveals + r * 64;
        const uint8_t *rev = reveals + r * 64 + 32;

        /* Find matching commitment */
        for (int i = 0; i < config->num_srv_commits; i++) {
            if (sodium_memcmp(config->srv_commits[i].identity_pk, pk, 32) == 0) {
                /* Verify: BLAKE2b(reveal) == commit */
                uint8_t expected[32];
                moor_crypto_hash(expected, rev, 32);
                if (sodium_memcmp(expected, config->srv_commits[i].commit, 32) == 0) {
                    memcpy(config->srv_commits[i].reveal, rev, 32);
                    config->srv_commits[i].revealed = 1;
                    LOG_INFO("SRV: verified reveal from DA %d", i);
                } else {
                    LOG_WARN("SRV: reveal mismatch from DA %d", i);
                }
                break;
            }
        }
    }
    return 0;
}

static int srv_cmp(const void *a, const void *b) {
    return sodium_memcmp(((const moor_srv_commitment_t *)a)->reveal,
                         ((const moor_srv_commitment_t *)b)->reveal, 32);
}

int moor_da_srv_compute(moor_da_config_t *config) {
    if (!config) return -1;

    /* Rotate: current -> previous */
    memcpy(config->srv_previous, config->srv_current, 32);

    /* Collect all revealed values, sort by reveal */
    moor_srv_commitment_t sorted[MOOR_MAX_DA_AUTHORITIES];
    int n = 0;
    for (int i = 0; i < config->num_srv_commits; i++) {
        if (config->srv_commits[i].revealed) {
            memcpy(&sorted[n], &config->srv_commits[i], sizeof(sorted[0]));
            n++;
        }
    }

    if (n == 0) {
        LOG_WARN("SRV: no reveals collected, using random");
        moor_crypto_random(config->srv_current, 32);
        return -1;
    }

    /* Sort by reveal for deterministic output */
    qsort(sorted, (size_t)n, sizeof(sorted[0]), srv_cmp);

    /* SRV = BLAKE2b(reveal_0 || reveal_1 || ... || reveal_n) */
    uint8_t concat[9 * 32]; /* max 9 DAs * 32 bytes */
    for (int i = 0; i < n; i++)
        memcpy(concat + i * 32, sorted[i].reveal, 32);

    moor_crypto_hash(config->srv_current, concat, (size_t)n * 32);

    /* Clear commits for next period */
    config->num_srv_commits = 0;

    LOG_INFO("SRV: computed shared random from %d reveals", n);
    return 0;
}

/* ================================================================
 * Consensus parameters
 * ================================================================ */
void moor_da_set_param(moor_da_config_t *config, const char *key, int32_t value) {
    if (!config || !key) return;

    /* Update existing */
    for (int i = 0; i < config->num_params; i++) {
        if (strcmp(config->params[i].key, key) == 0) {
            config->params[i].value = value;
            return;
        }
    }

    /* Add new */
    if (config->num_params >= MOOR_MAX_CONSENSUS_PARAMS) return;
    snprintf(config->params[config->num_params].key,
             sizeof(config->params[0].key), "%s", key);
    config->params[config->num_params].value = value;
    config->num_params++;
}

int32_t moor_consensus_get_param(const moor_da_config_t *config,
                                  const char *key, int32_t default_val) {
    if (!config || !key) return default_val;

    for (int i = 0; i < config->num_params; i++) {
        if (strcmp(config->params[i].key, key) == 0)
            return config->params[i].value;
    }
    return default_val;
}

/* ================================================================
 * Statistical relay flag assignment (Tor-aligned)
 *
 * Mirrors Tor's dirserv_compute_performance_thresholds() and
 * dirauth_set_routerstatus_from_routerinfo() from voteflags.c.
 *
 * Fast:   bandwidth >= 12.5th percentile (7/8 of relays get it)
 * Stable: uptime >= median uptime
 * Guard:  Fast + Stable + bw >= guard_bw_threshold + time_known >= 1/8th percentile
 * HSDir:  Fast + Stable + uptime >= 96 hours (MinUptimeHidServDirectory)
 * Exit:   relay self-declares, DA validates exit policy exists
 * ================================================================ */
static int cmp_u64_dir(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    return (va > vb) - (va < vb);
}

/* Minimum bandwidth to even consider a relay (4 KB/s, Tor's ABSOLUTE_MIN_VALUE) */
#define DA_MIN_BW_KB  4

/* Minimum uptime for HSDir flag (Tor: MinUptimeHidServDirectoryV2 = 96 hours) */
#define DA_HSDIR_MIN_UPTIME  (96 * 3600U)

/* Guard WFU threshold (simplified: we use uptime ratio as proxy) */
#define DA_GUARD_MIN_WFU  0.98

/* Guard: minimum time-known (8 days, Tor's AuthDirVoteGuardGuaranteeTimeKnown) */
#define DA_GUARD_MIN_TIME_KNOWN  (8 * 86400U)

void moor_da_compute_flags_statistical(moor_da_config_t *config) {
    if (!config) return;
    uint32_t n = config->consensus.num_relays;
    if (n == 0) return;

    /* Collect bandwidth and uptime for active relays (>= min BW) */
    uint64_t *bws = malloc(n * sizeof(uint64_t));
    uint64_t *uptimes = malloc(n * sizeof(uint64_t));
    uint64_t *guard_bws = malloc(n * sizeof(uint64_t));
    uint64_t *time_knowns = malloc(n * sizeof(uint64_t));
    if (!bws || !uptimes || !guard_bws || !time_knowns) {
        free(bws); free(uptimes); free(guard_bws); free(time_knowns);
        return;
    }

    uint64_t now = (uint64_t)time(NULL);
    uint32_t n_active = 0, n_guard_cand = 0;

    for (uint32_t i = 0; i < n; i++) {
        moor_node_descriptor_t *r = &config->consensus.relays[i];
        uint64_t eff_bw = moor_bw_auth_effective(r->bandwidth, r->verified_bandwidth);
        uint64_t bw_kb = eff_bw / 1000;
        if (bw_kb < DA_MIN_BW_KB) continue;

        uint64_t base = r->first_seen ? r->first_seen : r->published;
        uint64_t uptime = (now > base) ? (now - base) : 0;

        bws[n_active] = eff_bw;
        uptimes[n_active] = uptime;
        time_knowns[n_active] = uptime; /* time_known ≈ uptime for small networks */
        n_active++;

        /* Guard candidate BWs (exclude exits for threshold calc, like Tor) */
        if (!(r->flags & NODE_FLAG_EXIT)) {
            guard_bws[n_guard_cand++] = eff_bw;
        }
    }

    if (n_active == 0) {
        free(bws); free(uptimes); free(guard_bws); free(time_knowns);
        return;
    }

    /* Sort arrays for percentile computation */
    qsort(bws, n_active, sizeof(uint64_t), cmp_u64_dir);
    qsort(uptimes, n_active, sizeof(uint64_t), cmp_u64_dir);
    qsort(time_knowns, n_active, sizeof(uint64_t), cmp_u64_dir);
    if (n_guard_cand > 0)
        qsort(guard_bws, n_guard_cand, sizeof(uint64_t), cmp_u64_dir);

    /* --- Compute thresholds (Tor-aligned) --- */

    /* Fast: 12.5th percentile (n/8). Tor: find_nth_uint32(bws, n, n/8)
     * Most relays get Fast — only the bottom 12.5% don't. */
    uint64_t fast_bw = bws[n_active / 8];
    /* Floor: at least 4 KB/s */
    if (fast_bw < DA_MIN_BW_KB * 1000)
        fast_bw = DA_MIN_BW_KB * 1000;

    /* Stable: median uptime */
    uint64_t stable_uptime = uptimes[n_active / 2];

    /* Guard BW threshold: median of non-exit bandwidths
     * (Tor uses AuthDirVoteGuardBwThresholdFraction, default ~25th pct) */
    uint64_t guard_bw_threshold;
    if (n_guard_cand > 0)
        guard_bw_threshold = guard_bws[n_guard_cand / 2];
    else
        guard_bw_threshold = bws[n_active / 2]; /* fallback to overall median */

    /* Guard time-known: 12.5th percentile.
     * Tor uses 8 days as floor for 6000+ relay networks.  For networks
     * under 100 relays, trust self-declared Guard flags — stripping them
     * based on uptime would kill all guards when crossing the 20-relay
     * threshold (every relay restarts with fresh uptime).  The 8-day
     * floor only kicks in at 100+ relays where the anonymity set is
     * large enough that uptime-based Guard selection matters. */
    uint64_t guard_tk = time_knowns[n_active / 8];
    if (n_active >= 100 && guard_tk < DA_GUARD_MIN_TIME_KNOWN)
        guard_tk = DA_GUARD_MIN_TIME_KNOWN;

    /* --- Assign flags --- */
    for (uint32_t i = 0; i < n; i++) {
        moor_node_descriptor_t *r = &config->consensus.relays[i];
        uint64_t base = r->first_seen ? r->first_seen : r->published;
        uint64_t uptime = (now > base) ? (now - base) : 0;
        uint64_t eff_bw = moor_bw_auth_effective(r->bandwidth, r->verified_bandwidth);
        uint64_t bw_kb = eff_bw / 1000;

        /* Skip relays below minimum bandwidth */
        int active = (bw_kb >= DA_MIN_BW_KB);

        /* Fast: bandwidth >= 12.5th percentile */
        if (active && eff_bw >= fast_bw)
            r->flags |= NODE_FLAG_FAST;
        else
            r->flags &= ~NODE_FLAG_FAST;

        /* Stable: uptime >= median */
        if (active && uptime >= stable_uptime)
            r->flags |= NODE_FLAG_STABLE;
        else
            r->flags &= ~NODE_FLAG_STABLE;

        /* Guard: requires Fast + Stable + sufficient BW + time-known.
         * On small networks (<20 relays): trust self-declared Guard flag
         * immediately. Without this, fresh networks can't build circuits
         * because nobody has uptime to earn Guard. */
        if (n_active < 100) {
            /* Growing network (<100 relays): preserve self-declared Guard.
             * The 20-relay threshold that enables guard pinning must not
             * simultaneously strip all guards via uptime requirements. */
        } else if ((r->flags & NODE_FLAG_GUARD) &&
            (r->flags & NODE_FLAG_FAST) &&
            (r->flags & NODE_FLAG_STABLE) &&
            eff_bw >= guard_bw_threshold &&
            uptime >= guard_tk) {
            /* Large network: keep Guard if criteria met */
        } else if (r->flags & NODE_FLAG_GUARD) {
            /* Large network: strip if criteria not met */
            r->flags &= ~NODE_FLAG_GUARD;
        }

        /* Exit: relay must self-declare --exit. DA preserves it. */

        /* HSDir: Fast + Stable + uptime >= 96 hours (Tor's MinUptimeHidServDirectory).
         * On small networks (<20 relays), waive uptime requirement. */
        if ((r->flags & NODE_FLAG_FAST) &&
            (r->flags & NODE_FLAG_STABLE) &&
            (n_active < 20 || uptime >= DA_HSDIR_MIN_UPTIME)) {
            r->flags |= NODE_FLAG_HSDIR;
        } else {
            r->flags &= ~NODE_FLAG_HSDIR;
        }

        /* MiddleOnly: strip Guard/Exit/HSDir */
        if (r->flags & NODE_FLAG_MIDDLEONLY)
            r->flags &= ~(NODE_FLAG_GUARD | NODE_FLAG_EXIT | NODE_FLAG_HSDIR);
    }

    free(bws);
    free(uptimes);
    free(guard_bws);
    free(time_knowns);

    LOG_INFO("flags: Tor-aligned assignment (fast_bw=%llu, stable_up=%llus, "
             "guard_bw=%llu, guard_tk=%llus, %u/%u active relays)",
             (unsigned long long)fast_bw,
             (unsigned long long)stable_uptime,
             (unsigned long long)guard_bw_threshold,
             (unsigned long long)guard_tk,
             n_active, n);
}

/* ---- Directory Mirror (Relay-side consensus caching) ---- */

static moor_consensus_t g_dir_cache = {0};
static int              g_dir_cache_valid = 0;
static pthread_mutex_t  g_dir_cache_lock = PTHREAD_MUTEX_INITIALIZER;
/* Pre-serialized consensus snapshot (same text format the DA serves).
 * Swap atomically under g_dir_cache_lock so readers always see a
 * consistent pointer+length pair. */
static uint8_t         *g_dir_published_buf = NULL;
static int              g_dir_published_len = 0;
/* Compressed snapshot for bandwidth savings (~2.5x with zlib) */
static uint8_t         *g_dir_compressed_buf = NULL;
static size_t           g_dir_compressed_len = 0;

int moor_relay_dir_has_cache(void) {
    pthread_mutex_lock(&g_dir_cache_lock);
    int valid = g_dir_cache_valid;
    pthread_mutex_unlock(&g_dir_cache_lock);
    return valid;
}

/* Install a pre-fetched consensus into the dir cache.
 * Serializes, compresses, and atomically swaps the published snapshot. */
int moor_relay_dir_cache_update(const moor_consensus_t *fresh) {
    size_t buf_sz = moor_consensus_wire_size(fresh);
    if (buf_sz < 1024) buf_sz = 1024;
    uint8_t *buf = malloc(buf_sz);
    if (!buf) return -1;
    int len = moor_consensus_serialize(buf, buf_sz, fresh);
    if (len <= 0) { free(buf); return -1; }

    uint8_t *comp = NULL;
    size_t comp_len = 0;
    moor_consensus_compress(buf, (size_t)len, &comp, &comp_len);

    pthread_mutex_lock(&g_dir_cache_lock);
    uint8_t *old_buf = g_dir_published_buf;
    uint8_t *old_comp = g_dir_compressed_buf;
    moor_consensus_copy(&g_dir_cache, fresh);
    g_dir_published_buf = buf;
    g_dir_published_len = len;
    g_dir_compressed_buf = comp;
    g_dir_compressed_len = comp_len;
    g_dir_cache_valid = 1;
    pthread_mutex_unlock(&g_dir_cache_lock);

    free(old_buf);
    free(old_comp);
    LOG_INFO("dir mirror: cached consensus with %u relays (%d bytes, %zu compressed)",
             fresh->num_relays, len, comp_len);
    return 0;
}

int moor_relay_dir_cache_refresh(const char *da_address, uint16_t da_port) {
    moor_consensus_t *fresh = calloc(1, sizeof(moor_consensus_t));
    if (!fresh) return -1;
    if (moor_client_fetch_consensus(fresh, da_address, da_port) != 0) {
        LOG_WARN("dir mirror: failed to refresh consensus from DA");
        free(fresh);
        return -1;
    }
    int rc = moor_relay_dir_cache_update(fresh);
    moor_consensus_cleanup(fresh);
    free(fresh);
    return rc;
}

int moor_relay_dir_handle_request(int client_fd) {
    char req[512];
    ssize_t n = recv(client_fd, req, sizeof(req) - 1, 0);
    if (n <= 0) return -1;
    req[n] = '\0';

    /* Serve exit notice for HTTP GET requests (browsers hitting the dir_port) */
    if (strncmp(req, "GET ", 4) == 0) {
        size_t html_len = strlen(MOOR_EXIT_NOTICE_HTML);
        char hdr[256];
        int hdr_len = snprintf(hdr, sizeof(hdr),
            "HTTP/1.0 200 OK\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "\r\n", html_len);
        send(client_fd, hdr, (size_t)hdr_len, 0);
        send(client_fd, MOOR_EXIT_NOTICE_HTML, html_len, 0);
        return 0;
    }

    if (strncmp(req, "CONSENSUS", 9) != 0) {
        const char *err = "ERROR unknown request\n";
        send(client_fd, err, strlen(err), 0);
        return -1;
    }

    /* Serve pre-serialized consensus using the same wire format as the DA:
     *   len(4 bytes big-endian) + serialized text consensus (possibly compressed)
     * Clients call moor_client_fetch_consensus() which handles decompression
     * and verifies DA signatures — mirrors cannot forge consensus.
     * Hold g_dir_cache_lock during send to prevent free-during-send.
     * Bounded by the 5s socket send timeout set in relay_dir_accept_cb. */
    pthread_mutex_lock(&g_dir_cache_lock);
    if (!g_dir_cache_valid || !g_dir_published_buf || g_dir_published_len <= 0) {
        pthread_mutex_unlock(&g_dir_cache_lock);
        send(client_fd, "ERR\n", 4, 0);
        return -1;
    }

    const uint8_t *send_buf;
    size_t send_len;
    if (g_dir_compressed_buf && g_dir_compressed_len > 0) {
        send_buf = g_dir_compressed_buf;
        send_len = g_dir_compressed_len;
    } else {
        send_buf = g_dir_published_buf;
        send_len = (size_t)g_dir_published_len;
    }

    uint8_t len_buf[4];
    uint32_t sl = (uint32_t)send_len;
    len_buf[0] = (uint8_t)(sl >> 24);
    len_buf[1] = (uint8_t)(sl >> 16);
    len_buf[2] = (uint8_t)(sl >> 8);
    len_buf[3] = (uint8_t)(sl);

    int ok = (send(client_fd, (char *)len_buf, 4, 0) == 4 &&
              send(client_fd, (char *)send_buf, send_len, 0) == (ssize_t)send_len);
    pthread_mutex_unlock(&g_dir_cache_lock);

    if (ok)
        LOG_DEBUG("dir mirror: served consensus to client (%zu bytes)", send_len);
    return ok ? 0 : -1;
}

int moor_client_fetch_consensus_with_mirrors(moor_consensus_t *cons,
                                              const char *da_address, uint16_t da_port,
                                              const moor_consensus_t *cached_cons) {
    /* Try DA first */
    if (moor_client_fetch_consensus(cons, da_address, da_port) == 0)
        return 0;

    /* If we have a cached consensus, try random relays with dir_port */
    if (!cached_cons || cached_cons->num_relays == 0)
        return -1;

    LOG_INFO("DA unreachable, trying directory mirrors...");
    for (int attempt = 0; attempt < 3; attempt++) {
        /* Pick a random relay with dir_port > 0 */
        uint32_t idx;
        moor_crypto_random((uint8_t *)&idx, 4);
        idx %= cached_cons->num_relays;

        for (uint32_t i = 0; i < cached_cons->num_relays; i++) {
            uint32_t ri = (idx + i) % cached_cons->num_relays;
            const moor_node_descriptor_t *r = &cached_cons->relays[ri];
            if (r->dir_port == 0) continue;

            if (moor_client_fetch_consensus(cons, r->address, r->dir_port) == 0) {
                LOG_INFO("fetched consensus from mirror %s:%u",
                         r->address, r->dir_port);
                return 0;
            }
        }
    }

    return -1;
}
