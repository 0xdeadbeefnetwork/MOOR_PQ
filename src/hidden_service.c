#include "moor/moor.h"
#include "moor/kem.h"
#include <sodium.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <direct.h>
#include <io.h>
#include <fcntl.h>
#include <share.h>
#include <sys/stat.h>
#define close closesocket
#define MSG_NOSIGNAL 0
#define poll WSAPoll
#define mkdir(p, m) _mkdir(p)
/* Windows: _sopen_s with _S_IREAD|_S_IWRITE (no group/other bits) */
static FILE *secure_fopen(const char *path, const char *mode) {
    (void)mode;
    int fd;
    _sopen_s(&fd, path, _O_CREAT | _O_WRONLY | _O_TRUNC | _O_BINARY,
              _SH_DENYRW, _S_IREAD | _S_IWRITE);
    if (fd < 0) return NULL;
    return _fdopen(fd, "wb");
}
#else
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
/* Unix: open with 0600 permissions for secret key files.
 * O_NOFOLLOW prevents symlink attacks in data directories. */
static FILE *secure_fopen(const char *path, const char *mode) {
    (void)mode;
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) return NULL;
    return fdopen(fd, "wb");
}
#endif

/* Cross-platform wait-for-readable with timeout (ms). Returns >0 if readable */
static int hs_wait_for_readable(int fd, int timeout_ms)
{
#ifdef _WIN32
    fd_set rfds;
    struct timeval tv;
    FD_ZERO(&rfds);
    FD_SET((SOCKET)fd, &rfds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    return select(0, &rfds, NULL, NULL, &tv);
#else
    struct pollfd pfd = { fd, POLLIN, 0 };
    return poll(&pfd, 1, timeout_ms);
#endif
}

/* ================================================================
 * Client-side intro point failure cache
 *
 * Tor-style reachability cache.  When an INTRODUCE1 → RENDEZVOUS2 round trip
 * fails (timeout), we cache (service_pk, node_id) here so subsequent connect
 * attempts pick a different intro.  Entries expire after INTRO_FAIL_TTL_SEC
 * so a service whose intros all briefly failed can recover after it
 * republishes.  Concurrent access: mark from main thread (RV2 timeout),
 * is_failed from worker thread (intro selection).
 * ================================================================ */
#define MOOR_HS_INTRO_FAIL_CACHE 64
#define MOOR_HS_INTRO_FAIL_TTL_SEC 300  /* 5 min; slightly > intro rotation */

typedef struct {
    uint8_t  service_pk[32];
    uint8_t  node_id[32];
    uint64_t expires_at;   /* 0 = slot empty */
} hs_intro_fail_t;

static hs_intro_fail_t g_intro_fail[MOOR_HS_INTRO_FAIL_CACHE];
static pthread_mutex_t g_intro_fail_mutex = PTHREAD_MUTEX_INITIALIZER;

static void intro_fail_purge_expired_locked(uint64_t now) {
    for (int i = 0; i < MOOR_HS_INTRO_FAIL_CACHE; i++) {
        if (g_intro_fail[i].expires_at != 0 &&
            g_intro_fail[i].expires_at <= now) {
            memset(&g_intro_fail[i], 0, sizeof(g_intro_fail[i]));
        }
    }
}

void moor_hs_intro_mark_failed(const uint8_t service_pk[32],
                                const uint8_t node_id[32]) {
    if (!service_pk || !node_id) return;
    uint64_t now = (uint64_t)time(NULL);
    uint64_t expires = now + MOOR_HS_INTRO_FAIL_TTL_SEC;
    pthread_mutex_lock(&g_intro_fail_mutex);
    intro_fail_purge_expired_locked(now);
    /* Replace existing entry (refresh TTL) or find empty slot. */
    int empty_slot = -1, oldest_slot = 0;
    uint64_t oldest_exp = UINT64_MAX;
    for (int i = 0; i < MOOR_HS_INTRO_FAIL_CACHE; i++) {
        if (g_intro_fail[i].expires_at == 0) {
            if (empty_slot < 0) empty_slot = i;
            continue;
        }
        if (memcmp(g_intro_fail[i].service_pk, service_pk, 32) == 0 &&
            memcmp(g_intro_fail[i].node_id, node_id, 32) == 0) {
            g_intro_fail[i].expires_at = expires;
            pthread_mutex_unlock(&g_intro_fail_mutex);
            return;
        }
        if (g_intro_fail[i].expires_at < oldest_exp) {
            oldest_exp = g_intro_fail[i].expires_at;
            oldest_slot = i;
        }
    }
    int slot = empty_slot >= 0 ? empty_slot : oldest_slot;
    memcpy(g_intro_fail[slot].service_pk, service_pk, 32);
    memcpy(g_intro_fail[slot].node_id, node_id, 32);
    g_intro_fail[slot].expires_at = expires;
    pthread_mutex_unlock(&g_intro_fail_mutex);
}

int moor_hs_intro_is_failed(const uint8_t service_pk[32],
                             const uint8_t node_id[32]) {
    if (!service_pk || !node_id) return 0;
    uint64_t now = (uint64_t)time(NULL);
    pthread_mutex_lock(&g_intro_fail_mutex);
    intro_fail_purge_expired_locked(now);
    int found = 0;
    for (int i = 0; i < MOOR_HS_INTRO_FAIL_CACHE; i++) {
        if (g_intro_fail[i].expires_at == 0) continue;
        if (memcmp(g_intro_fail[i].service_pk, service_pk, 32) == 0 &&
            memcmp(g_intro_fail[i].node_id, node_id, 32) == 0) {
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_intro_fail_mutex);
    return found;
}

void moor_hs_intro_clear_failures_for(const uint8_t service_pk[32]) {
    if (!service_pk) return;
    pthread_mutex_lock(&g_intro_fail_mutex);
    for (int i = 0; i < MOOR_HS_INTRO_FAIL_CACHE; i++) {
        if (g_intro_fail[i].expires_at == 0) continue;
        if (memcmp(g_intro_fail[i].service_pk, service_pk, 32) == 0) {
            memset(&g_intro_fail[i], 0, sizeof(g_intro_fail[i]));
        }
    }
    pthread_mutex_unlock(&g_intro_fail_mutex);
}

int moor_hs_compute_address(char *out, size_t out_len,
                            const uint8_t identity_pk[32],
                            const uint8_t *kem_pk, size_t kem_pk_len,
                            const uint8_t *falcon_pk, size_t falcon_pk_len) {
    /* PQ-committed address format (v3):
     *   base32(Ed25519_pk(32) + BLAKE2b_16(kem_pk || falcon_pk)(16)) + ".moor"
     *
     * The 16-byte commit over (ML-KEM pk || Falcon-512 pk) binds the address
     * to BOTH post-quantum keys. An adversary that breaks Ed25519 still
     * cannot substitute a different KEM or Falcon pk — that would require
     * BLAKE2b preimage resistance. Falcon binding future-proofs HS identity
     * once Ed25519 is broken: clients can reject descriptors whose Falcon pk
     * doesn't match the address commit.
     *
     * Backwards compat:
     *   - Both NULL  -> v1 address (32-byte Ed25519 only).
     *   - Only kem_pk -> v2 address (old format, KEM-only commit).
     *   - Both set  -> v3 address (kem_pk || falcon_pk commit). */
    uint8_t addr_data[48]; /* 32 (Ed25519) + 16 (PQ hash) */
    size_t addr_data_len;

    memcpy(addr_data, identity_pk, 32);

    if (kem_pk && kem_pk_len > 0) {
        uint8_t commit_buf[1184 + MOOR_FALCON_PK_LEN];
        size_t commit_len = 0;
        if (kem_pk_len > sizeof(commit_buf)) return -1;
        memcpy(commit_buf, kem_pk, kem_pk_len);
        commit_len = kem_pk_len;
        if (falcon_pk && falcon_pk_len > 0) {
            if (commit_len + falcon_pk_len > sizeof(commit_buf)) return -1;
            memcpy(commit_buf + commit_len, falcon_pk, falcon_pk_len);
            commit_len += falcon_pk_len;
        }
        uint8_t full_hash[32];
        moor_crypto_hash(full_hash, commit_buf, commit_len);
        memcpy(addr_data + 32, full_hash, 16);
        addr_data_len = 48;
    } else {
        addr_data_len = 32; /* v1 compat */
    }

    char b32[128];
    int b32_len = moor_base32_encode(b32, sizeof(b32), addr_data, addr_data_len);
    if (b32_len < 0) return -1;

    if ((size_t)b32_len + 6 > out_len) return -1;
    memcpy(out, b32, b32_len);
    memcpy(out + b32_len, ".moor", 6);
    return 0;
}

/* Derive descriptor encryption key from service identity.
 * Only someone who knows the identity_pk can derive this key.
 * The DA only has address_hash = BLAKE2b(identity_pk) and
 * cannot reverse the hash to obtain the pk. */
static void derive_desc_key(uint8_t desc_key[32],
                            const uint8_t identity_pk[32],
                            uint64_t time_period) {
    uint8_t input[49]; /* "moor-desc" (9) + identity_pk (32) + time_period (8) */
    memcpy(input, "moor-desc", 9);
    memcpy(input + 9, identity_pk, 32);
    for (int i = 0; i < 8; i++)
        input[41 + i] = (uint8_t)(time_period >> (i * 8));
    moor_crypto_hash(desc_key, input, 49);
}

static uint64_t current_time_period(void) {
    return (uint64_t)time(NULL) / MOOR_TIME_PERIOD_SECS;
}

int moor_hs_keygen(moor_hs_config_t *config) {
    moor_crypto_sign_keygen(config->identity_pk, config->identity_sk);
    moor_crypto_box_keygen(config->onion_pk, config->onion_sk);

    /* Generate ML-KEM + Falcon-512 keypairs for PQ HS identity — BEFORE
     * computing address so both PQ pks are baked into the .moor commit. */
    moor_kem_keygen(config->kem_pk, config->kem_sk);
    config->kem_generated = 1;

    if (moor_falcon_keygen(config->falcon_pk, config->falcon_sk) != 0) {
        LOG_ERROR("HS: failed to generate Falcon-512 keypair");
        return -1;
    }
    config->falcon_generated = 1;

    /* PQ-committed address: base32(Ed25519_pk + BLAKE2b_16(kem_pk || falcon_pk)) */
    moor_hs_compute_address(config->moor_address, sizeof(config->moor_address),
                            config->identity_pk,
                            config->kem_pk, sizeof(config->kem_pk),
                            config->falcon_pk, sizeof(config->falcon_pk));

    /* Derive initial blinded keys for current time period */
    config->current_time_period = current_time_period();
    moor_crypto_blind_keypair(config->blinded_pk, config->blinded_sk,
                              config->identity_pk, config->identity_sk,
                              config->current_time_period);
    LOG_INFO("generated HS keys (PQ-committed address)");
    return 0;
}

int moor_hs_save_keys(const moor_hs_config_t *config) {
    if (strlen(config->hs_dir) > 480) {
        LOG_ERROR("hs_dir path too long (max 480 chars)");
        return -1;
    }

    /* Create directory */
    mkdir(config->hs_dir, 0700);

    char path[512];

    /* Save identity keypair (secret key: restricted permissions) */
    snprintf(path, sizeof(path), "%s/identity_sk", config->hs_dir);
    FILE *f = secure_fopen(path, "wb");
    if (!f) return -1;
    if (fwrite(config->identity_sk, 1, 64, f) != 64) {
        LOG_ERROR("failed to write %s", path);
        fclose(f);
        return -1;
    }
    fflush(f);
    fclose(f);

    snprintf(path, sizeof(path), "%s/identity_pk", config->hs_dir);
    f = fopen(path, "wb");
    if (!f) return -1;
    if (fwrite(config->identity_pk, 1, 32, f) != 32) {
        LOG_ERROR("failed to write %s", path);
        fclose(f);
        return -1;
    }
    fflush(f);
    fclose(f);

    /* Save onion keypair (secret key: restricted permissions) */
    snprintf(path, sizeof(path), "%s/onion_sk", config->hs_dir);
    f = secure_fopen(path, "wb");
    if (!f) return -1;
    if (fwrite(config->onion_sk, 1, 32, f) != 32) {
        LOG_ERROR("failed to write %s", path);
        fclose(f);
        return -1;
    }
    fflush(f);
    fclose(f);

    snprintf(path, sizeof(path), "%s/onion_pk", config->hs_dir);
    f = fopen(path, "wb");
    if (!f) return -1;
    if (fwrite(config->onion_pk, 1, 32, f) != 32) {
        LOG_ERROR("failed to write %s", path);
        fclose(f);
        return -1;
    }
    fflush(f);
    fclose(f);

    /* Save KEM keypair if generated (PQ hybrid e2e) */
    if (config->kem_generated) {
        snprintf(path, sizeof(path), "%s/kem_sk", config->hs_dir);
        f = secure_fopen(path, "wb");
        if (!f) return -1;
        if (fwrite(config->kem_sk, 1, sizeof(config->kem_sk), f) !=
            sizeof(config->kem_sk)) {
            LOG_ERROR("failed to write %s", path);
            fclose(f);
            return -1;
        }
        fflush(f);
        fclose(f);

        /* Save kem_sk path before overwriting for cleanup on failure (#R1-D2) */
        char kem_sk_path[512];
        snprintf(kem_sk_path, sizeof(kem_sk_path), "%s/kem_sk", config->hs_dir);

        snprintf(path, sizeof(path), "%s/kem_pk", config->hs_dir);
        f = fopen(path, "wb");
        if (!f) {
            /* Wipe sk on partial write to avoid orphaned secret key (CWE-459) */
            sodium_memzero((void *)config->kem_sk, sizeof(config->kem_sk));
            unlink(kem_sk_path);
            return -1;
        }
        if (fwrite(config->kem_pk, 1, sizeof(config->kem_pk), f) !=
            sizeof(config->kem_pk)) {
            LOG_ERROR("failed to write %s", path);
            fclose(f);
            sodium_memzero((void *)config->kem_sk, sizeof(config->kem_sk));
            unlink(kem_sk_path);
            return -1;
        }
        fflush(f);
        fclose(f);
    }

    /* Save Falcon-512 keypair if generated (PQ HS identity) */
    if (config->falcon_generated) {
        snprintf(path, sizeof(path), "%s/falcon_sk", config->hs_dir);
        f = secure_fopen(path, "wb");
        if (!f) return -1;
        if (fwrite(config->falcon_sk, 1, sizeof(config->falcon_sk), f) !=
            sizeof(config->falcon_sk)) {
            LOG_ERROR("failed to write %s", path);
            fclose(f);
            return -1;
        }
        fflush(f);
        fclose(f);

        char falcon_sk_path[512];
        snprintf(falcon_sk_path, sizeof(falcon_sk_path), "%s/falcon_sk", config->hs_dir);

        snprintf(path, sizeof(path), "%s/falcon_pk", config->hs_dir);
        f = fopen(path, "wb");
        if (!f) {
            sodium_memzero((void *)config->falcon_sk, sizeof(config->falcon_sk));
            unlink(falcon_sk_path);
            return -1;
        }
        if (fwrite(config->falcon_pk, 1, sizeof(config->falcon_pk), f) !=
            sizeof(config->falcon_pk)) {
            LOG_ERROR("failed to write %s", path);
            fclose(f);
            sodium_memzero((void *)config->falcon_sk, sizeof(config->falcon_sk));
            unlink(falcon_sk_path);
            return -1;
        }
        fflush(f);
        fclose(f);
    }

    /* Save address */
    snprintf(path, sizeof(path), "%s/hostname", config->hs_dir);
    f = fopen(path, "w");
    if (!f) return -1;
    if (fprintf(f, "%s\n", config->moor_address) < 0) {
        LOG_ERROR("failed to write %s", path);
        fclose(f);
        return -1;
    }
    fflush(f);
    fclose(f);

    LOG_INFO("HS keys saved to %s", config->hs_dir);
    return 0;
}

/* Open file for reading without following symlinks (CWE-59) */
static FILE *nofollow_fopen(const char *path) {
#ifdef _WIN32
    return fopen(path, "rb");
#else
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return NULL;
    return fdopen(fd, "rb");
#endif
}

int moor_hs_load_keys(moor_hs_config_t *config) {
    if (strlen(config->hs_dir) > 480) {
        LOG_ERROR("hs_dir path too long (max 480 chars)");
        return -1;
    }

    char path[512];

    snprintf(path, sizeof(path), "%s/identity_sk", config->hs_dir);
    FILE *f = nofollow_fopen(path);
    if (!f) return -1;
    if (fread(config->identity_sk, 1, 64, f) != 64) { fclose(f); return -1; }
    fclose(f);

    snprintf(path, sizeof(path), "%s/identity_pk", config->hs_dir);
    f = nofollow_fopen(path);
    if (!f) return -1;
    if (fread(config->identity_pk, 1, 32, f) != 32) { fclose(f); return -1; }
    fclose(f);

    snprintf(path, sizeof(path), "%s/onion_sk", config->hs_dir);
    f = nofollow_fopen(path);
    if (!f) return -1;
    if (fread(config->onion_sk, 1, 32, f) != 32) { fclose(f); return -1; }
    fclose(f);

    snprintf(path, sizeof(path), "%s/onion_pk", config->hs_dir);
    f = nofollow_fopen(path);
    if (!f) return -1;
    if (fread(config->onion_pk, 1, 32, f) != 32) { fclose(f); return -1; }
    fclose(f);

    /* Load KEM keypair if it exists (PQ hybrid e2e) — before computing
     * address so the KEM pk hash is included in the .moor address.
     * If missing, generate + persist fresh ML-KEM-768 keys. */
    snprintf(path, sizeof(path), "%s/kem_sk", config->hs_dir);
    f = nofollow_fopen(path);
    if (f) {
        if (fread(config->kem_sk, 1, sizeof(config->kem_sk), f) ==
            sizeof(config->kem_sk)) {
            fclose(f);
            snprintf(path, sizeof(path), "%s/kem_pk", config->hs_dir);
            f = nofollow_fopen(path);
            if (f && fread(config->kem_pk, 1, sizeof(config->kem_pk), f) ==
                sizeof(config->kem_pk)) {
                config->kem_generated = 1;
                LOG_INFO("HS KEM keys loaded");
            }
            if (f) fclose(f);
        } else {
            fclose(f);
        }
    }

    if (!config->kem_generated) {
        if (moor_kem_keygen(config->kem_pk, config->kem_sk) != 0) {
            LOG_ERROR("HS: failed to generate ML-KEM keypair");
            return -1;
        }
        config->kem_generated = 1;
        LOG_INFO("HS: generated fresh ML-KEM-768 keypair (no prior kem_sk on disk)");

        snprintf(path, sizeof(path), "%s/kem_sk", config->hs_dir);
        f = fopen(path, "wb");
        if (!f) { LOG_ERROR("HS: failed to open %s", path); return -1; }
        if (fwrite(config->kem_sk, 1, sizeof(config->kem_sk), f) !=
            sizeof(config->kem_sk)) {
            LOG_ERROR("HS: short write on %s", path);
            fclose(f);
            return -1;
        }
        fclose(f);
        chmod(path, 0600);

        snprintf(path, sizeof(path), "%s/kem_pk", config->hs_dir);
        f = fopen(path, "wb");
        if (!f) { LOG_ERROR("HS: failed to open %s", path); return -1; }
        if (fwrite(config->kem_pk, 1, sizeof(config->kem_pk), f) !=
            sizeof(config->kem_pk)) {
            LOG_ERROR("HS: short write on %s", path);
            fclose(f);
            return -1;
        }
        fclose(f);
    }

    /* Load Falcon-512 keypair if it exists — before computing address so the
     * Falcon pk hash is included in the v3 .moor commit. Regen-on-missing. */
    snprintf(path, sizeof(path), "%s/falcon_sk", config->hs_dir);
    f = nofollow_fopen(path);
    if (f) {
        if (fread(config->falcon_sk, 1, sizeof(config->falcon_sk), f) ==
            sizeof(config->falcon_sk)) {
            fclose(f);
            snprintf(path, sizeof(path), "%s/falcon_pk", config->hs_dir);
            f = nofollow_fopen(path);
            if (f && fread(config->falcon_pk, 1, sizeof(config->falcon_pk), f) ==
                sizeof(config->falcon_pk)) {
                config->falcon_generated = 1;
                LOG_INFO("HS Falcon-512 keys loaded");
            }
            if (f) fclose(f);
        } else {
            fclose(f);
        }
    }

    if (!config->falcon_generated) {
        if (moor_falcon_keygen(config->falcon_pk, config->falcon_sk) != 0) {
            LOG_ERROR("HS: failed to generate Falcon-512 keypair");
            return -1;
        }
        config->falcon_generated = 1;
        LOG_INFO("HS: generated fresh Falcon-512 keypair (no prior falcon_sk on disk)");

        snprintf(path, sizeof(path), "%s/falcon_sk", config->hs_dir);
        f = fopen(path, "wb");
        if (!f) { LOG_ERROR("HS: failed to open %s", path); return -1; }
        if (fwrite(config->falcon_sk, 1, sizeof(config->falcon_sk), f) !=
            sizeof(config->falcon_sk)) {
            LOG_ERROR("HS: short write on %s", path);
            fclose(f);
            return -1;
        }
        fclose(f);
        chmod(path, 0600);

        snprintf(path, sizeof(path), "%s/falcon_pk", config->hs_dir);
        f = fopen(path, "wb");
        if (!f) { LOG_ERROR("HS: failed to open %s", path); return -1; }
        if (fwrite(config->falcon_pk, 1, sizeof(config->falcon_pk), f) !=
            sizeof(config->falcon_pk)) {
            LOG_ERROR("HS: short write on %s", path);
            fclose(f);
            return -1;
        }
        fclose(f);
    }

    /* Compute PQ-committed .moor address (binds ML-KEM + Falcon pks). */
    moor_hs_compute_address(config->moor_address, sizeof(config->moor_address),
                            config->identity_pk,
                            config->kem_generated ? config->kem_pk : NULL,
                            config->kem_generated ? sizeof(config->kem_pk) : 0,
                            config->falcon_generated ? config->falcon_pk : NULL,
                            config->falcon_generated ? sizeof(config->falcon_pk) : 0);

    /* Derive blinded keys for current time period */
    config->current_time_period = current_time_period();
    moor_crypto_blind_keypair(config->blinded_pk, config->blinded_sk,
                              config->identity_pk, config->identity_sk,
                              config->current_time_period);

    /* Ensure hostname file exists (may be missing after a kem key regen) */
    snprintf(path, sizeof(path), "%s/hostname", config->hs_dir);
    if (access(path, F_OK) != 0) {
        f = fopen(path, "w");
        if (f) {
            fprintf(f, "%s\n", config->moor_address);
            fclose(f);
        }
    }

    /* Restore monotonic state across restarts: without these calls the
     * revision counter resets to 0 on every restart, and clients with a
     * warm anti-replay cache reject all fresh descriptors as stale. */
    moor_hs_load_revision(config);
    moor_hs_load_pow_seed(config);

    LOG_INFO("HS keys loaded (PQ-committed address)");
    return 0;
}

/*
 * Build a 3-hop circuit using vanguards for the middle hops.
 * Guard is selected normally (or from persisted guard state).
 * Middle (hop 2) is restricted to L2 vanguards (rotate ~24h).
 * Exit/last (hop 3) is restricted to L3 vanguards (rotate ~1h).
 * This prevents guard discovery attacks on hidden services.
 */
int moor_hs_build_circuit(moor_circuit_t *circ,
                          moor_connection_t *guard_conn,
                          const moor_consensus_t *consensus,
                          const moor_vanguard_set_t *vg,
                          const uint8_t our_pk[32],
                          const uint8_t our_sk[64]) {
    circ->circuit_id = moor_circuit_gen_id();
    circ->is_client = 1;
    circ->conn = guard_conn;

    uint8_t exclude[96]; /* up to 3 * 32 */
    memcpy(exclude, our_pk, 32);

    /* Select guard: use Prop 271 pinning when network is large enough
     * to provide meaningful anonymity set (>= 20 relays).
     * Small networks: random selection (pinning is pointless with 3 relays). */
    const moor_node_descriptor_t *guard = NULL;
    if (consensus->num_relays >= 20) {
        const moor_guard_entry_t *ge = moor_guard_select(moor_pathbias_get_state());
        if (ge) {
            for (uint32_t ri = 0; ri < consensus->num_relays; ri++) {
                if (sodium_memcmp(consensus->relays[ri].identity_pk,
                                  ge->identity_pk, 32) == 0 &&
                    (consensus->relays[ri].flags & NODE_FLAG_RUNNING)) {
                    guard = &consensus->relays[ri];
                    break;
                }
            }
        }
    }
    if (!guard) {
        guard = moor_node_select_relay(consensus, NODE_FLAG_GUARD | NODE_FLAG_RUNNING,
                                       exclude, 1);
    }
    if (!guard) {
        guard = moor_node_select_relay(consensus, NODE_FLAG_RUNNING,
                                       exclude, 1);
    }
    if (!guard) {
        LOG_ERROR("hs circuit: no guard relay");
        return -1;
    }

    memcpy(guard_conn->peer_identity, guard->identity_pk, 32);
    if (guard_conn->state != CONN_STATE_OPEN) {
        if (moor_connection_connect(guard_conn, guard->address, guard->or_port,
                                    our_pk, our_sk, NULL, NULL) != 0)
            return -1;
    }
    guard_conn->circuit_refcount++;

    memcpy(circ->hops[0].node_id, guard->identity_pk, 32);
    if (moor_circuit_create(circ, guard->identity_pk, guard->onion_pk) != 0)
        return -1;

    /* Middle: use L2 vanguard (restricted set, rotates 24h) */
    memcpy(exclude + 32, guard->identity_pk, 32);
    const moor_node_descriptor_t *middle = NULL;
    if (vg && vg->num_l2 > 0) {
        middle = moor_vanguard_select_l2(vg, consensus, exclude, 2);
    }
    if (!middle) {
        /* Fallback to normal selection if no vanguards available */
        middle = moor_node_select_relay(consensus, NODE_FLAG_RUNNING, exclude, 2);
    }
    if (!middle) {
        LOG_ERROR("hs circuit: no middle relay");
        return -1;
    }

    if (moor_circuit_extend(circ, middle) != 0)
        return -1;

    /* Third hop: use L3 vanguard (restricted set, rotates 1h) */
    memcpy(exclude + 64, middle->identity_pk, 32);
    const moor_node_descriptor_t *third = NULL;
    if (vg && vg->num_l3 > 0) {
        third = moor_vanguard_select_l3(vg, consensus, exclude, 3);
    }
    if (!third) {
        third = moor_node_select_relay(consensus, NODE_FLAG_RUNNING, exclude, 3);
    }
    if (!third) {
        LOG_ERROR("hs circuit: no third relay");
        return -1;
    }

    if (moor_circuit_extend(circ, third) != 0)
        return -1;

    LOG_INFO("hs circuit %u: guard + L2 vanguard + L3 vanguard",
             circ->circuit_id);
    return 0;
}

/* Build HS circuit targeting a specific relay as the last hop (for RP) */
static int moor_hs_build_circuit_to_rp(moor_circuit_t *circ,
                                        moor_connection_t *guard_conn,
                                        const moor_consensus_t *consensus,
                                        const moor_vanguard_set_t *vg,
                                        const uint8_t our_pk[32],
                                        const uint8_t our_sk[64],
                                        const uint8_t rp_node_id[32]) {
    /* Find RP relay in consensus */
    if (!consensus) {
        LOG_ERROR("hs rp circuit: no consensus available");
        return -1;
    }
    const moor_node_descriptor_t *rp_relay = NULL;
    for (uint32_t i = 0; i < consensus->num_relays; i++) {
        if (sodium_memcmp(consensus->relays[i].identity_pk,
                          rp_node_id, 32) == 0) {
            rp_relay = &consensus->relays[i];
            break;
        }
    }
    if (!rp_relay) {
        LOG_ERROR("hs rp circuit: RP node not in consensus");
        return -1;
    }

    circ->circuit_id = moor_circuit_gen_id();
    circ->is_client = 1;
    circ->conn = guard_conn;

    uint8_t exclude[96];
    memcpy(exclude, our_pk, 32);

    /* Select guard (must not be the RP) */
    memcpy(exclude + 32, rp_node_id, 32);
    const moor_node_descriptor_t *guard =
        moor_node_select_relay(consensus, NODE_FLAG_GUARD | NODE_FLAG_RUNNING,
                               exclude, 2);
    if (!guard) {
        /* No guard available (e.g., only guard relay is the RP itself).
         * Fall back to any running relay as circuit entry. */
        guard = moor_node_select_relay(consensus, NODE_FLAG_RUNNING,
                                       exclude, 2);
    }
    if (!guard) {
        LOG_ERROR("hs rp circuit: no guard relay");
        return -1;
    }

    memcpy(guard_conn->peer_identity, guard->identity_pk, 32);
    if (guard_conn->state != CONN_STATE_OPEN) {
        if (moor_connection_connect(guard_conn, guard->address, guard->or_port,
                                    our_pk, our_sk, NULL, NULL) != 0)
            return -1;
    }
    guard_conn->circuit_refcount++;

    memcpy(circ->hops[0].node_id, guard->identity_pk, 32);
    if (moor_circuit_create(circ, guard->identity_pk, guard->onion_pk) != 0)
        return -1;

    /* Middle: use L2 vanguard if available, exclude guard and RP */
    uint8_t exclude2[96];
    memcpy(exclude2, our_pk, 32);
    memcpy(exclude2 + 32, guard->identity_pk, 32);
    memcpy(exclude2 + 64, rp_node_id, 32);
    const moor_node_descriptor_t *middle = NULL;
    if (vg && vg->num_l2 > 0) {
        middle = moor_vanguard_select_l2(vg, consensus, exclude2, 3);
    }
    if (!middle) {
        middle = moor_node_select_relay(consensus, NODE_FLAG_RUNNING,
                                        exclude2, 3);
    }
    if (!middle) {
        LOG_ERROR("hs rp circuit: no middle relay");
        return -1;
    }

    if (moor_circuit_extend(circ, middle) != 0)
        return -1;

    /* Third hop: the specific RP relay */
    if (moor_circuit_extend(circ, rp_relay) != 0)
        return -1;

    circ->cc_path_type = MOOR_CC_PATH_ONION;
    LOG_INFO("hs rp circuit %u: 3-hop path built", circ->circuit_id);
    return 0;
}

int moor_hs_establish_intro(moor_hs_config_t *config,
                            const moor_consensus_t *consensus) {
    /* Build circuits to introduction points and establish them.
     * Tor-aligned: configurable 3-10 intro points (default 3).
     *
     * Backfill: iterate ALL slots 0..desired-1 and rebuild any NULL
     * entries.  Previous code only appended past num_intro_circuits,
     * so dead slots at lower indices were never re-established and
     * the HS became permanently unreachable once all slots died. */
    int desired = config->desired_intro_points > 0 ?
                  config->desired_intro_points : MOOR_DEFAULT_INTRO_POINTS;
    if (desired > MOOR_MAX_INTRO_POINTS) desired = MOOR_MAX_INTRO_POINTS;

    /* Cap desired by available relays — can't have more intro points
     * than relays. Without this, unfillable slots are permanently NULL
     * and the rotation timer keeps re-triggering re-establishment. */
    int max_intros = (int)consensus->num_relays;
    if (desired > max_intros) desired = max_intros;

    /* Set num_intro_circuits to desired so rotation checks all slots */
    if (config->num_intro_circuits < desired)
        config->num_intro_circuits = desired;
    /* Shrink if desired decreased (e.g., relays left the network) */
    if (config->num_intro_circuits > desired)
        config->num_intro_circuits = desired;

    int established = 0;
    for (int i = 0; i < desired; i++) {
        /* Skip slots that already have a live circuit */
        if (config->intro_circuits[i]) {
            established++;
            continue;
        }

        /* Build a circuit to the intro point (retry up to 5 times) */
        moor_circuit_t *circ = NULL;
        moor_connection_t *conn = NULL;
        int built = 0;
        for (int retry = 0; retry < 5 && !built; retry++) {
            circ = moor_circuit_alloc();
            if (!circ) break;
            conn = moor_connection_alloc();
            if (!conn) { moor_circuit_free(circ); circ = NULL; break; }
            if (moor_hs_build_circuit(circ, conn, consensus,
                                       &config->vanguards,
                                       config->identity_pk,
                                       config->identity_sk) == 0) {
                built = 1;
            } else {
                moor_circuit_free(circ); circ = NULL;
                moor_connection_free(conn); conn = NULL;
                LOG_INFO("HS: intro circuit build retry %d/5", retry + 1);
            }
        }
        if (!built) continue;
        circ->cc_path_type = MOOR_CC_PATH_ONION; /* HS intro circuit */

        /* Send RELAY_ESTABLISH_INTRO with blinded key.
         * Intro point sees blinded_pk, not identity_pk.
         * Payload: blinded_pk(32) + signature(64) [+ pow_seed(32) + pow_difficulty(1)]
         * Signature is made with blinded_sk so intro point can verify. */
        uint8_t intro_data[96 + 33]; /* max: with PoW params */
        size_t intro_data_len = 96;
        memcpy(intro_data, config->blinded_pk, 32);
        moor_crypto_sign_blinded(intro_data + 32, config->blinded_pk, 32,
                                 config->blinded_sk, config->blinded_pk);

        /* Append PoW params if enabled */
        if (config->pow_enabled && config->pow_difficulty > 0) {
            memcpy(intro_data + 96, config->pow_seed, 32);
            intro_data[128] = (uint8_t)config->pow_difficulty;
            intro_data_len = 129;
        }

        moor_cell_t cell;
        moor_cell_relay(&cell, circ->circuit_id, RELAY_ESTABLISH_INTRO, 0,
                       intro_data, (uint16_t)intro_data_len);
        if (moor_circuit_encrypt_forward(circ, &cell) != 0 ||
            moor_connection_send_cell(circ->conn, &cell) != 0) {
            LOG_WARN("HS: failed to send ESTABLISH_INTRO");
            moor_circuit_destroy(circ);
            if (conn->fd >= 0)
                moor_connection_close(conn);
            else
                moor_connection_free(conn);
            continue;
        }

        /* Wait for RELAY_INTRO_ESTABLISHED from the intro relay.
         * Without this, we'd publish the descriptor before the relay
         * has registered our intro point — clients send INTRODUCE1
         * to a relay that doesn't know about us yet. */
        {
            moor_cell_t resp;
            int got_ack = 0;
            uint64_t deadline = (uint64_t)time(NULL) + 10;
            while ((uint64_t)time(NULL) < deadline) {
                int ret = moor_connection_recv_cell(circ->conn, &resp);
                if (ret > 0) {
                    if (resp.command == CELL_PADDING) continue;
                    if (resp.circuit_id != circ->circuit_id) {
                        if (circ->conn->on_other_cell)
                            circ->conn->on_other_cell(circ->conn, &resp);
                        continue;
                    }
                    if (resp.command == CELL_DESTROY) {
                        LOG_WARN("HS: DESTROY while waiting for INTRO_ESTABLISHED");
                        break;
                    }
                    if (resp.command == CELL_RELAY) {
                        if (moor_circuit_decrypt_backward(circ, &resp) == 0) {
                            moor_relay_payload_t rp;
                            moor_relay_unpack(&rp, resp.payload);
                            if (rp.relay_command == RELAY_INTRO_ESTABLISHED) {
                                got_ack = 1;
                                LOG_INFO("HS: INTRO_ESTABLISHED received for slot %d", i);
                            } else {
                                LOG_WARN("HS: unexpected relay cmd %d waiting for INTRO_ESTABLISHED",
                                         rp.relay_command);
                            }
                        }
                        break;
                    }
                    continue;
                }
                if (ret < 0) break;
                struct pollfd pfd = { circ->conn->fd, POLLIN, 0 };
                if (poll(&pfd, 1, 5000) <= 0) break;
            }
            if (!got_ack) {
                LOG_WARN("HS: INTRO_ESTABLISHED timeout for slot %d, dropping", i);
                moor_circuit_destroy(circ);
                if (conn->fd >= 0)
                    moor_connection_close(conn);
                else
                    moor_connection_free(conn);
                continue;
            }
        }

        config->intro_circuits[i] = circ;
        config->intro_established_at[i] = (uint64_t)time(NULL);
        config->intro_count[i] = 0;
        established++;

        LOG_INFO("HS: established intro point at slot %d", i);
    }

    LOG_INFO("HS: %d introduction points established", established);
    return (established > 0) ? 0 : -1;
}

int moor_hs_publish_descriptor(moor_hs_config_t *config) {
    /*
     * Build the plaintext descriptor, then encrypt it so the DA
     * only sees the address_hash (lookup key). The DA cannot read
     * the intro points, onion key, or service identity.
     *
     * Encrypted wire format (v2):
     *   address_hash(32) + ver(1=0x02) + nonce(12) + AEAD(plaintext_desc, ad=address_hash)
     *
     * desc_key = BLAKE2b("moor-desc" || identity_pk || time_period)
     */

    /* Advance revision counter monotonically. Floor to wall-clock so that a
     * restart which lost the persisted counter still produces a revision
     * that beats any warm client anti-replay cache — revision always ≥ now. */
    uint64_t now_rev = (uint64_t)time(NULL);
    if (config->desc_revision < now_rev)
        config->desc_revision = now_rev;
    else
        config->desc_revision++;
    moor_hs_save_revision(config);

    /* Build plaintext descriptor */
    moor_hs_descriptor_t desc;
    memset(&desc, 0, sizeof(desc));

    moor_crypto_hash(desc.address_hash, config->identity_pk, 32);
    memcpy(desc.service_pk, config->identity_pk, 32);
    memcpy(desc.onion_pk, config->onion_pk, 32);
    memcpy(desc.blinded_pk, config->blinded_pk, 32);
    desc.revision = config->desc_revision;
    /* Collect only LIVE intro circuits into the descriptor.
     * Previous code used num_intro_circuits (the desired count) which
     * included dead/NULL slots, publishing zero node_ids that clients
     * can't look up in their consensus — making the HS unreachable. */
    desc.num_intro_points = 0;
    for (int i = 0; i < config->num_intro_circuits &&
         desc.num_intro_points < MOOR_MAX_INTRO_POINTS; i++) {
        moor_circuit_t *circ = config->intro_circuits[i];
        if (circ && circ->num_hops > 0 &&
            circ->conn && circ->conn->state == CONN_STATE_OPEN) {
            int last = circ->num_hops - 1;
            int slot = desc.num_intro_points++;
            memcpy(desc.intro_points[slot].node_id,
                   circ->hops[last].node_id, 32);
        }
    }
    if (desc.num_intro_points == 0) {
        LOG_ERROR("HS: no live intro circuits — cannot publish descriptor");
        return -1;
    }

    /* Populate PoW fields if enabled */
    if (config->pow_enabled && config->pow_difficulty > 0) {
        memcpy(desc.pow_seed, config->pow_seed, 32);
        desc.pow_difficulty = (uint8_t)config->pow_difficulty;
    }

    /* PQ hybrid e2e: publish Kyber768 public key in descriptor */
    if (config->kem_generated) {
        memcpy(desc.kem_pk, config->kem_pk, 1184);
        desc.kem_available = 1;
    }

    /* PQ HS identity: publish Falcon-512 pk so clients can verify the
     * .moor address commits to this pk (and, in future revisions, verify
     * Falcon signatures over the descriptor body). */
    if (config->falcon_generated) {
        memcpy(desc.falcon_pk, config->falcon_pk, sizeof(config->falcon_pk));
        desc.falcon_available = 1;
    }

    /* Fix #182: Sign address_hash + service_pk + BLAKE2b(critical fields).
     * Old signature only covered (address_hash, service_pk), allowing an attacker
     * who can derive desc_key (from public identity_pk + time_period) to decrypt,
     * modify intro points / PoW params, re-encrypt, and re-publish with valid sig.
     * Now covers blinded_pk, intro_points, pow_seed, pow_difficulty.
     * Excludes onion_pk so signature verifies with client-auth (zeroed onion_pk). */
    /* 32 blinded + 4 nip + MOOR_MAX_INTRO_POINTS*32 + 32 pow_seed + 1 pow_diff + 8 revision */
    uint8_t extra_buf[32 + 4 + MOOR_MAX_INTRO_POINTS * 32 + 32 + 1 + 8];
    size_t epos = 0;
    memcpy(extra_buf + epos, desc.blinded_pk, 32); epos += 32;
    uint32_t nip = desc.num_intro_points;
    memcpy(extra_buf + epos, &nip, 4); epos += 4;
    for (uint32_t ip = 0; ip < nip && ip < MOOR_MAX_INTRO_POINTS; ip++) {
        memcpy(extra_buf + epos, desc.intro_points[ip].node_id, 32); epos += 32;
    }
    memcpy(extra_buf + epos, desc.pow_seed, 32); epos += 32;
    extra_buf[epos++] = desc.pow_difficulty;
    /* Include revision counter in signature to prevent replay */
    extra_buf[epos++] = (uint8_t)(desc.revision >> 56);
    extra_buf[epos++] = (uint8_t)(desc.revision >> 48);
    extra_buf[epos++] = (uint8_t)(desc.revision >> 40);
    extra_buf[epos++] = (uint8_t)(desc.revision >> 32);
    extra_buf[epos++] = (uint8_t)(desc.revision >> 24);
    extra_buf[epos++] = (uint8_t)(desc.revision >> 16);
    extra_buf[epos++] = (uint8_t)(desc.revision >> 8);
    extra_buf[epos++] = (uint8_t)(desc.revision);
    uint8_t content_hash[32];
    moor_crypto_hash(content_hash, extra_buf, epos);

    uint8_t to_sign[96]; /* address_hash(32) + service_pk(32) + content_hash(32) */
    memcpy(to_sign, desc.address_hash, 32);
    memcpy(to_sign + 32, desc.service_pk, 32);
    memcpy(to_sign + 64, content_hash, 32);
    if (moor_crypto_sign(desc.signature, to_sign, 96, config->identity_sk) != 0) {
        LOG_ERROR("HS: descriptor signing failed");
        sodium_memzero(&desc, sizeof(desc));
        return -1;
    }
    desc.published = (uint64_t)time(NULL);

    /* Serialize the plaintext descriptor (before client-auth encryption).
     * Buffer must fit KEM pk (1184 bytes) + auth entries (16*80) + other fields.
     * Worst case: 1717 base + 1281 auth = 2998, rounded up to 4096. */
    uint8_t plaintext[4096];
    int pt_len = moor_hs_descriptor_serialize(plaintext, sizeof(plaintext), &desc);
    if (pt_len < 0) {
        sodium_memzero(&desc, sizeof(desc));
        sodium_memzero(plaintext, sizeof(plaintext));
        return -1;
    }

    /* Tor-aligned inner plaintext padding: pad to 128-byte boundary.
     * Prevents fingerprinting by exact descriptor size within the outer
     * 10KB bucket. (Tor: HS_DESC_PLAINTEXT_PADDING_MULTIPLE = 128) */
    #define HS_DESC_INNER_PAD 128
    {
        size_t padded = (((size_t)pt_len + HS_DESC_INNER_PAD - 1) / HS_DESC_INNER_PAD) * HS_DESC_INNER_PAD;
        if (padded > sizeof(plaintext)) padded = sizeof(plaintext);
        if (padded > (size_t)pt_len) {
            moor_crypto_random(plaintext + pt_len, padded - (size_t)pt_len);
            pt_len = (int)padded;
        }
    }

    /* Client-auth superencryption: wrap the entire serialized descriptor
     * in a second layer that only authorized clients can decrypt.
     *
     * Format of superencrypted body:
     *   auth_type(1) + num_entries(1) + sealed_inner_key[N](N*48) +
     *   inner_nonce(8) + AEAD(plaintext, ad="moor-hs-auth", key=inner_key)
     *
     * This hides intro points, PoW params, and all metadata from anyone
     * who doesn't hold a listed client key. The outer desc_key layer
     * (derived from identity_pk) is still present for DA-opaque storage. */
    uint8_t to_encrypt[4096]; /* buffer for outer AEAD input (fits superencrypted PQ desc) */
    size_t to_encrypt_len;

    if (config->num_auth_clients > 0) {
        /* Generate random inner key for this descriptor */
        uint8_t inner_key[32];
        moor_crypto_random(inner_key, 32);

        /* PQ-seal inner_key to each authorized client.
         * Each sealed entry is MOOR_KEM_CT_LEN(1088) + 32(payload) + 16(AEAD tag)
         * = 1136 bytes (vs 48 bytes for the old Curve25519 sealed box). */
        #define PQ_AUTH_ENTRY_LEN (MOOR_KEM_CT_LEN + 32 + MOOR_PQ_SEAL_AEAD_TAG)
        uint8_t super_buf[2 + MOOR_MAX_AUTH_CLIENTS * PQ_AUTH_ENTRY_LEN + 8 + sizeof(plaintext) + 16];
        size_t spos = 0;
        int num_ac = config->num_auth_clients;
        if (num_ac > MOOR_MAX_AUTH_CLIENTS) num_ac = MOOR_MAX_AUTH_CLIENTS;
        if (num_ac < 0) num_ac = 0;
        super_buf[spos++] = 3; /* auth_type 3 = PQ-sealed superencrypted descriptor */
        super_buf[spos++] = (uint8_t)num_ac;
        for (int i = 0; i < num_ac; i++) {
            if (moor_crypto_pq_seal(super_buf + spos,
                                    inner_key, 32,
                                    config->auth_clients[i].kem_pk) != 0) {
                moor_crypto_wipe(inner_key, 32);
                sodium_memzero(&desc, sizeof(desc));
                sodium_memzero(super_buf, sizeof(super_buf));
                LOG_ERROR("HS: PQ-seal failed for auth client %d", i);
                return -1;
            }
            spos += PQ_AUTH_ENTRY_LEN;
        }

        /* Inner AEAD: encrypt full descriptor with inner_key */
        uint64_t inner_nonce;
        moor_crypto_random((uint8_t *)&inner_nonce, 8);
        for (int i = 7; i >= 0; i--)
            super_buf[spos++] = (uint8_t)(inner_nonce >> (i * 8));

        uint8_t inner_ct[sizeof(plaintext) + 16];
        size_t inner_ct_len;
        const uint8_t inner_ad[] = "moor-hs-auth";
        if (moor_crypto_aead_encrypt(inner_ct, &inner_ct_len,
                                      plaintext, pt_len,
                                      inner_ad, 12,
                                      inner_key, inner_nonce) != 0) {
            moor_crypto_wipe(inner_key, 32);
            sodium_memzero(&desc, sizeof(desc));
            sodium_memzero(super_buf, sizeof(super_buf));
            sodium_memzero(to_encrypt, sizeof(to_encrypt));
            return -1;
        }
        memcpy(super_buf + spos, inner_ct, inner_ct_len);
        spos += inner_ct_len;
        moor_crypto_wipe(inner_key, 32);

        memcpy(to_encrypt, super_buf, spos);
        to_encrypt_len = (int)spos;
        sodium_memzero(super_buf, sizeof(super_buf));
        LOG_INFO("HS: descriptor superencrypted for %d authorized clients",
                 config->num_auth_clients);
    } else {
        /* No client auth: outer layer encrypts raw descriptor */
        memcpy(to_encrypt, plaintext, pt_len);
        to_encrypt_len = pt_len;
    }
    sodium_memzero(plaintext, sizeof(plaintext));

    /* Tor-aligned descriptor padding: pad to fixed size to prevent
     * fingerprinting by descriptor size.  Tor uses 10KB but MOOR's
     * buffer architecture uses 2KB.  Pad to 1KB multiples. */
    #define HS_DESC_PAD_MULTIPLE ((size_t)1024)
    size_t padded_len = ((to_encrypt_len / HS_DESC_PAD_MULTIPLE) + 1) * HS_DESC_PAD_MULTIPLE;
    if (padded_len > sizeof(to_encrypt)) padded_len = sizeof(to_encrypt);
    if (padded_len > to_encrypt_len) {
        moor_crypto_random(to_encrypt + to_encrypt_len, padded_len - to_encrypt_len);
        to_encrypt_len = padded_len;
    }

    /* Derive outer encryption key (anyone with the .moor address can derive this) */
    uint8_t desc_key[32];
    derive_desc_key(desc_key, config->identity_pk, current_time_period());

    /* v2 descriptor: 96-bit nonce.  Birthday bound at 2^48 vs 2^32 for v1.
     * Wire format: address_hash(32) + version(1=0x02) + nonce(12) + ciphertext. */
    uint8_t nonce12[12];
    moor_crypto_random(nonce12, 12);

    /* Outer encrypt: AEAD(body, ad=address_hash, key=desc_key, nonce) */
    uint8_t ciphertext[sizeof(to_encrypt) + 16];
    size_t ct_len;
    if (moor_crypto_aead_encrypt_n12(ciphertext, &ct_len,
                                      to_encrypt, to_encrypt_len,
                                      desc.address_hash, 32,
                                      desc_key, nonce12) != 0) {
        moor_crypto_wipe(desc_key, 32);
        sodium_memzero(to_encrypt, sizeof(to_encrypt));
        return -1;
    }
    moor_crypto_wipe(desc_key, 32);

    /* Build encrypted wire data: address_hash(32) + ver(1) + nonce(12) + ciphertext */
    uint8_t wire[sizeof(ciphertext) + 32 + 1 + 12];
    size_t wire_len = 0;
    memcpy(wire, desc.address_hash, 32); wire_len += 32;
    wire[wire_len++] = 0x02; /* descriptor version 2 */
    memcpy(wire + wire_len, nonce12, 12); wire_len += 12;
    memcpy(wire + wire_len, ciphertext, ct_len); wire_len += ct_len;

    if (wire_len > UINT16_MAX) {
        LOG_ERROR("HS: wire_len %zu exceeds uint16_t max", wire_len);
        sodium_memzero(to_encrypt, sizeof(to_encrypt));
        return -1;
    }

    /* Publish to all configured DAs (best-effort, first success is enough) */
    uint8_t send_buf[11 + 4 + sizeof(wire)]; /* match wire[] max */
    memcpy(send_buf, "HS_PUBLISH\n", 11);
    send_buf[11] = (uint8_t)(wire_len >> 24);
    send_buf[12] = (uint8_t)(wire_len >> 16);
    send_buf[13] = (uint8_t)(wire_len >> 8);
    send_buf[14] = (uint8_t)(wire_len);
    memcpy(send_buf + 15, wire, wire_len);

    int any_ok = 0;
    int da_count = config->num_das > 0 ? config->num_das : 1;
    for (int d = 0; d < da_count; d++) {
        const char *addr = config->num_das > 0 ?
            config->da_list[d].address : config->da_address;
        uint16_t port = config->num_das > 0 ?
            config->da_list[d].port : config->da_port;

        int fd = moor_tcp_connect_simple(addr, port);
        if (fd < 0) {
            LOG_WARN("HS: cannot reach DA %s:%u for publish", addr, port);
            continue;
        }
        moor_set_socket_timeout(fd, MOOR_DA_REQUEST_TIMEOUT);
        send(fd, (char *)send_buf, 15 + wire_len, MSG_NOSIGNAL);

        char resp[16];
        recv(fd, resp, sizeof(resp), 0);
        close(fd);
        any_ok = 1;
        LOG_INFO("HS: descriptor published to DA %s:%u", addr, port);
    }
    if (!any_ok) {
        LOG_ERROR("HS: failed to publish descriptor to any DA");
        sodium_memzero(&desc, sizeof(desc));
        sodium_memzero(plaintext, sizeof(plaintext));
        sodium_memzero(to_encrypt, sizeof(to_encrypt));
        return -1;
    }

    /* Publish to DHT for decentralized storage.
     * SKIP when called from the event loop (periodic republish / intro
     * re-establishment) because the synchronous DHT circuit builds block
     * the event loop for 20-30 seconds, killing intro and RP circuits.
     * DHT publish only happens at init time (before event loop starts). */
    if (!config->skip_dht_publish &&
        config->cached_consensus &&
        config->cached_consensus->num_relays > 0) {
        uint64_t tp = current_time_period();
        const moor_consensus_t *cons = config->cached_consensus;

        /* Current time period: 3 replicas */
        moor_dht_publish(desc.address_hash, wire, (uint16_t)wire_len,
                          cons, cons->srv_current,
                          tp, config->da_address, config->da_port);
        LOG_INFO("HS: DHT publish to current time period (tp=%lu)", (unsigned long)tp);

        /* Previous time period: 3 replicas with previous SRV.
         * Different SRV → different ring positions → different replicas. */
        if (tp > 0) {
            uint8_t zero_srv[32] = {0};
            if (sodium_memcmp(cons->srv_previous, zero_srv, 32) != 0) {
                moor_dht_publish(desc.address_hash, wire, (uint16_t)wire_len,
                                  cons, cons->srv_previous,
                                  tp - 1, config->da_address, config->da_port);
                LOG_INFO("HS: DHT publish to previous time period (tp=%lu)",
                         (unsigned long)(tp - 1));
            }
        }
    }

    /* Wipe sensitive stack buffers */
    sodium_memzero(&desc, sizeof(desc));
    sodium_memzero(plaintext, sizeof(plaintext));
    sodium_memzero(to_encrypt, sizeof(to_encrypt));

    return 0;
}

int moor_hs_init(moor_hs_config_t *config,
                 const moor_consensus_t *consensus) {
    /* Try to load existing keys, generate if not found */
    if (moor_hs_load_keys(config) != 0) {
        LOG_INFO("generating new HS keys");
        moor_hs_keygen(config);
        moor_hs_save_keys(config);
    }

    LOG_INFO("hidden service initialized");

    /* Generate PoW seed if PoW is enabled */
    if (config->pow_enabled && config->pow_difficulty > 0) {
        moor_crypto_random(config->pow_seed, 32);
        LOG_INFO("HS PoW enabled: difficulty=%d", config->pow_difficulty);
    }

    /* Initialize vanguards: restricted middle hops to prevent guard discovery.
     * Try to load persisted vanguards first, then refresh expired ones. */
    if (moor_vanguard_load(&config->vanguards, config->hs_dir) != 0)
        memset(&config->vanguards, 0, sizeof(config->vanguards));
    moor_vanguard_init(&config->vanguards, consensus,
                       config->identity_pk, 1);
    moor_vanguard_save(&config->vanguards, config->hs_dir);

    /* Establish introduction points */
    if (moor_hs_establish_intro(config, consensus) != 0) {
        LOG_ERROR("failed to establish intro points");
        return -1;
    }

    /* Publish encrypted descriptor to DA */
    if (moor_hs_publish_descriptor(config) != 0) {
        LOG_ERROR("failed to publish HS descriptor");
        return -1;
    }

    return 0;
}

int moor_hs_handle_introduce(moor_hs_config_t *config,
                             moor_circuit_t *intro_circ,
                             const uint8_t *payload, size_t len) {
    /*
     * INTRODUCE2 payload is PQ-sealed (ML-KEM-768 + ChaCha20-Poly1305)
     * to our KEM pk. Decrypt to get:
     *   rp_node_id(32) + rendezvous_cookie(20) + client_eph_pk(32)
     * The introduction point cannot read this payload.
     */
    if (len < 84 + MOOR_PQ_SEAL_OVERHEAD) {
        LOG_ERROR("INTRODUCE2 payload too short for PQ sealed box (%zu)", len);
        return -1;
    }

    uint8_t decrypted[84];
    if (moor_crypto_pq_seal_open(decrypted, payload, 84 + MOOR_PQ_SEAL_OVERHEAD,
                                  config->kem_sk) != 0) {
        LOG_ERROR("INTRODUCE2: PQ sealed box decryption failed");
        return -1;
    }

    /* Count only decrypt-validated introductions. Otherwise an attacker who
     * can reach the intro point (e.g. a hostile middle relay on the intro
     * circuit) could pump garbage cells to inflate the counter and force
     * premature intro-point rotation. */
    for (int i = 0; i < config->num_intro_circuits; i++) {
        if (config->intro_circuits[i] == intro_circ) {
            config->intro_count[i]++;
            break;
        }
    }

    uint8_t rp_node_id[32];
    uint8_t rendezvous_cookie[MOOR_RENDEZVOUS_COOKIE_LEN];
    uint8_t client_eph_pk[32];

    memcpy(rp_node_id, decrypted, 32);
    memcpy(rendezvous_cookie, decrypted + 32, 20);
    memcpy(client_eph_pk, decrypted + 52, 32);

    moor_crypto_wipe(decrypted, sizeof(decrypted));

    /* Replay cache keyed on (rendezvous_cookie, client_eph_pk): a replayed
     * INTRODUCE2 would cause us to build a second rendezvous circuit to the
     * same cookie, wasting our circuit budget and leaking intro-point
     * activity. Time-bounded so a legitimate client that somehow reuses
     * eph_pk (buggy retry) eventually recovers. */
    {
        #define INTRO2_REPLAY_SLOTS 512
        #define INTRO2_REPLAY_TTL   600   /* 10 minutes */
        static uint8_t seen_cookies[INTRO2_REPLAY_SLOTS][20 + 32];
        static uint64_t seen_time[INTRO2_REPLAY_SLOTS];
        static uint32_t seen_next = 0;
        uint8_t key[20 + 32];
        memcpy(key, rendezvous_cookie, 20);
        memcpy(key + 20, client_eph_pk, 32);
        uint64_t now = (uint64_t)time(NULL);
        for (uint32_t si = 0; si < INTRO2_REPLAY_SLOTS; si++) {
            if (seen_time[si] == 0) continue;
            if (now - seen_time[si] > INTRO2_REPLAY_TTL) continue;
            if (sodium_memcmp(seen_cookies[si], key, sizeof(key)) == 0) {
                LOG_WARN("INTRODUCE2: rejected replay");
                moor_crypto_wipe(key, sizeof(key));
                return -1;
            }
        }
        memcpy(seen_cookies[seen_next], key, sizeof(key));
        seen_time[seen_next] = now;
        seen_next = (seen_next + 1) % INTRO2_REPLAY_SLOTS;
        moor_crypto_wipe(key, sizeof(key));
    }

    /* Build circuit to rendezvous point -- use cached consensus if available */
    return moor_hs_rendezvous(config, rendezvous_cookie, client_eph_pk,
                               rp_node_id, config->cached_consensus);
}

int moor_hs_rendezvous(moor_hs_config_t *config,
                       const uint8_t *rendezvous_cookie,
                       const uint8_t *client_ephemeral_pk,
                       const uint8_t *rp_node_id,
                       const moor_consensus_t *consensus) {
    /* Generate our ephemeral key for the rendezvous DH */
    uint8_t eph_pk[32], eph_sk[32];
    moor_crypto_box_keygen(eph_pk, eph_sk);

    /* DH with client's ephemeral key */
    uint8_t shared[32];
    if (moor_crypto_dh(shared, eph_sk, client_ephemeral_pk) != 0) {
        moor_crypto_wipe(eph_sk, 32);
        return -1;
    }

    /* Build RELAY_RENDEZVOUS1 payload:
     *   rendezvous_cookie(20) + our_eph_pk(32) + key_hash(32) */
    uint8_t rv1_data[84];
    memcpy(rv1_data, rendezvous_cookie, 20);
    memcpy(rv1_data + 20, eph_pk, 32);
    uint8_t key_hash[32];
    moor_crypto_hash(key_hash, shared, 32);
    memcpy(rv1_data + 52, key_hash, 32);

    moor_consensus_t *heap_cons = NULL;
    if (!consensus) {
        /* Fetch consensus if not provided -- heap-alloc to avoid ~3.5MB stack */
        heap_cons = calloc(1, sizeof(moor_consensus_t));
        if (!heap_cons) {
            LOG_ERROR("HS rendezvous: calloc failed");
            moor_crypto_wipe(shared, 32);
            moor_crypto_wipe(eph_sk, 32);
            return -1;
        }
        LOG_INFO("HS rendezvous: fetching consensus from %s:%u",
                 config->da_address, config->da_port);
        if (moor_client_fetch_consensus(heap_cons, config->da_address,
                                         config->da_port) != 0) {
            LOG_ERROR("HS rendezvous: consensus fetch failed");
            free(heap_cons);
            moor_crypto_wipe(shared, 32);
            moor_crypto_wipe(eph_sk, 32);
            return -1;
        }
        LOG_INFO("HS rendezvous: got consensus with %u relays",
                 heap_cons->num_relays);
        consensus = heap_cons;
    }

    /* Build circuit specifically to the RP relay */
    moor_circuit_t *rp_circ = NULL;
    moor_connection_t *rp_conn = NULL;
    int built = 0;
    for (int retry = 0; retry < 5 && !built; retry++) {
        rp_circ = moor_circuit_alloc();
        rp_conn = moor_connection_alloc();
        if (!rp_circ || !rp_conn) {
            if (rp_circ) moor_circuit_free(rp_circ);
            if (rp_conn) moor_connection_free(rp_conn);
            rp_circ = NULL; rp_conn = NULL;
            break;
        }
        if (moor_hs_build_circuit_to_rp(rp_circ, rp_conn, consensus,
                                         &config->vanguards,
                                         config->identity_pk,
                                         config->identity_sk,
                                         rp_node_id) == 0) {
            built = 1;
        } else {
            moor_circuit_free(rp_circ); rp_circ = NULL;
            moor_connection_free(rp_conn); rp_conn = NULL;
            LOG_INFO("HS: rendezvous circuit build retry %d/5", retry + 1);
        }
    }
    if (!built) {
        LOG_ERROR("HS rendezvous: failed to build RP circuit after 5 retries");
        free(heap_cons);
        moor_crypto_wipe(shared, 32);
        moor_crypto_wipe(eph_sk, 32);
        return -1;
    }

    LOG_INFO("HS rendezvous: RP circuit built, sending RENDEZVOUS1");
    /* Send RELAY_RENDEZVOUS1 through the circuit */
    moor_cell_t cell;
    moor_cell_relay(&cell, rp_circ->circuit_id, RELAY_RENDEZVOUS1, 0,
                   rv1_data, sizeof(rv1_data));
    if (moor_circuit_encrypt_forward(rp_circ, &cell) != 0 ||
        moor_connection_send_cell(rp_circ->conn, &cell) != 0) {
        LOG_ERROR("HS rendezvous: failed to send RENDEZVOUS1");
        /* Tear down the RP circuit properly. Order matters:
         *   1. mark_for_close (via moor_circuit_destroy) defers DESTROY
         *      sends to end-of-loop via close_all_marked.
         *   2. moor_connection_close nullifies circ->conn refs to rp_conn
         *      BEFORE freeing it, so close_all_marked's deferred DESTROY
         *      pass sees conn==NULL and skips — no UAF.
         * Previously: close(fd)+connection_free left circ->conn dangling. */
        moor_circuit_destroy(rp_circ);
        moor_connection_close(rp_conn);
        free(heap_cons);
        moor_crypto_wipe(shared, 32);
        moor_crypto_wipe(eph_sk, 32);
        return -1;
    }

    LOG_INFO("HS: RENDEZVOUS1 sent");

    /* Store RP circuit for event loop registration (reuse freed slots) */
    {
        int slot = -1;
        for (int s = 0; s < 8; s++) {
            if (config->rp_circuits[s] == NULL) {
                slot = s;
                break;
            }
        }
        if (slot >= 0) {
            config->rp_circuits[slot] = rp_circ;
            config->rp_connections[slot] = rp_conn;
            if (slot >= config->num_rp_circuits)
                config->num_rp_circuits = slot + 1;
            LOG_INFO("HS: stored RP circuit %d (fd=%d)", slot, rp_conn->fd);
        } else {
            LOG_WARN("HS: no free RP circuit slots (all 8 in use)");
            moor_circuit_destroy(rp_circ);
            if (rp_conn->fd >= 0) close(rp_conn->fd);
            moor_connection_free(rp_conn);
            free(heap_cons);
            moor_crypto_wipe(shared, 32);
            moor_crypto_wipe(eph_sk, 32);
            return -1;
        }
    }

    free(heap_cons);
    /* Derive e2e keys for RP circuit (#197) — HS: send=subkey 1, recv=subkey 0 */
    moor_crypto_kdf(rp_circ->e2e_send_key, 32, shared, 1, "moore2e!");
    moor_crypto_kdf(rp_circ->e2e_recv_key, 32, shared, 0, "moore2e!");
    rp_circ->e2e_send_nonce = 0;
    rp_circ->e2e_recv_nonce = 0;
    rp_circ->e2e_active = 1;

    /* Save DH shared for PQ hybrid rekey when client sends KEM CT */
    if (config->kem_generated) {
        memcpy(rp_circ->e2e_dh_shared, shared, 32);
        rp_circ->e2e_kem_pending = 1;
        rp_circ->e2e_kem_ct_len = 0;
        LOG_INFO("HS: e2e keys derived, awaiting PQ KEM upgrade");
    } else {
        LOG_INFO("HS: e2e keys derived for RP circuit (classical only)");
    }
    moor_crypto_wipe(shared, 32);
    moor_crypto_wipe(eph_sk, 32);
    return 0;
}

/* Fragment send callback: encrypt each fragment forward through the
 * client's intro circuit and ship it to the guard. ctx = intro circuit. */
static int hs_client_intro_send_cb(uint32_t circuit_id, uint8_t relay_cmd,
                                    uint16_t stream_id,
                                    const uint8_t *data, uint16_t data_len,
                                    void *ctx) {
    moor_circuit_t *intro_circ = (moor_circuit_t *)ctx;
    moor_cell_t cell;
    moor_cell_relay(&cell, circuit_id, relay_cmd, stream_id, data, data_len);
    if (moor_circuit_encrypt_forward(intro_circ, &cell) != 0)
        return -1;
    return moor_connection_send_cell(intro_circ->conn, &cell);
}

int moor_hs_client_connect_start(const char *moor_address,
                                  moor_circuit_t **rp_circuit_out,
                                  const moor_consensus_t *consensus,
                                  const char *da_address, uint16_t da_port,
                                  const uint8_t our_pk[32],
                                  const uint8_t our_sk[64],
                                  uint8_t *hs_kem_pk_out,
                                  int *hs_kem_available_out,
                                  uint8_t *intro_node_id_out) {
    if (hs_kem_available_out) *hs_kem_available_out = 0;
    if (intro_node_id_out) memset(intro_node_id_out, 0, 32);
    LOG_DEBUG("connecting to hidden service");

    /* Decode .moor address to extract identity_pk and optional PQ commitment.
     * v1: base32(Ed25519_pk(32)) + ".moor"              — 52 chars + .moor
     * v2: base32(Ed25519_pk(32) + KEM_hash(16)) + ".moor" — 77 chars + .moor */
    size_t addr_len = strlen(moor_address);
    if (addr_len <= 5) return -1;

    char b32_part[128];
    size_t b32_len = addr_len - 5; /* minus ".moor" */
    if (b32_len >= sizeof(b32_part)) return -1;
    memcpy(b32_part, moor_address, b32_len);
    b32_part[b32_len] = '\0';

    /* Decode base32 — 32 bytes (v1) or 48 bytes (v2 with PQ commitment) */
    uint8_t addr_data[48];
    int decoded_len = moor_base32_decode(addr_data, sizeof(addr_data),
                                          b32_part, b32_len);
    if (decoded_len < 32) {
        LOG_ERROR("HS: failed to decode .moor address (got %d bytes)", decoded_len);
        return -1;
    }
    uint8_t service_pk[32];
    memcpy(service_pk, addr_data, 32);
    int has_pq_commitment = (decoded_len >= 48);
    uint8_t pq_commitment[16];
    if (has_pq_commitment)
        memcpy(pq_commitment, addr_data + 32, 16);

    /* Compute address_hash for DA lookup: BLAKE2b(identity_pk) */
    uint8_t lookup_hash[32];
    moor_crypto_hash(lookup_hash, service_pk, 32);

    /* Try DHT fetch first, fall back to DA.
     * Dual time-period: try current period, then previous period. */
    moor_hs_descriptor_t hs_desc;
    int desc_fetched = 0;
    /* Outer decrypted body — may be raw descriptor or superencrypted */
    uint8_t outer_pt[MOOR_DHT_MAX_DESC_DATA];
    size_t outer_pt_len = 0;

    if (consensus && consensus->num_relays > 0) {
        uint64_t tp = (uint64_t)time(NULL) / MOOR_TIME_PERIOD_SECS;

        /* Try current time period, then previous */
        for (int period = 0; period < 2 && !desc_fetched; period++) {
            uint64_t try_tp = (period == 0) ? tp : (tp > 0 ? tp - 1 : 0);
            const uint8_t *try_srv = (period == 0) ?
                consensus->srv_current : consensus->srv_previous;
            uint8_t zero_srv[32] = {0};
            if (period == 1 && sodium_memcmp(try_srv, zero_srv, 32) == 0)
                continue; /* no previous SRV available */

            uint8_t dht_data[MOOR_DHT_MAX_DESC_DATA];
            uint16_t dht_len = 0;
            if (moor_dht_fetch(lookup_hash, dht_data, &dht_len,
                                consensus, try_srv, try_tp,
                                da_address, da_port) == 0 && dht_len > 0) {
                /* v2: addr_hash(32) + ver(1=0x02) + nonce(12) + ct+16 */
                if (dht_len < 32 + 1 + 12 + 16) continue;
                if (dht_data[32] != 0x02) continue; /* reject v1 / unknown */

                uint8_t desc_key[32];
                derive_desc_key(desc_key, service_pk, try_tp);

                const uint8_t *nonce12 = dht_data + 33;
                size_t ct_len = dht_len - (32 + 1 + 12);

                uint8_t *pt = malloc(ct_len);
                if (pt) {
                    if (moor_crypto_aead_decrypt_n12(pt, &outer_pt_len,
                                                     dht_data + 45, ct_len,
                                                     dht_data, 32,
                                                     desc_key, nonce12) == 0 &&
                        outer_pt_len <= sizeof(outer_pt)) {
                        memcpy(outer_pt, pt, outer_pt_len);
                        desc_fetched = 1;
                        LOG_INFO("HS: descriptor fetched via DHT (tp=%lu)",
                                 (unsigned long)try_tp);
                    }
                    sodium_memzero(pt, ct_len);
                    free(pt);
                }
                moor_crypto_wipe(desc_key, 32);
            }
        }
    }

    /* Fall back to DA if DHT failed */
    if (!desc_fetched) {
        if (moor_client_fetch_hs_descriptor(&hs_desc, da_address, da_port,
                                             lookup_hash, service_pk) != 0) {
            LOG_ERROR("failed to fetch HS descriptor");
            return -1;
        }
        /* DA path returns deserialized descriptor directly — skip to verify */
        goto verify_descriptor;
    }

    /* Decrypt superencrypted descriptor if client auth is required.
     * auth_type 3 = PQ-sealed superencryption (ML-KEM-768 per client).
     * auth_type 1 = legacy (only onion_pk sealed per client, Curve25519). */
    if (outer_pt_len > 0 && outer_pt[0] == 3) {
        /* PQ-sealed format: auth_type(1) + num_entries(1) +
         * pq_sealed_inner_key[N](N*PQ_AUTH_ENTRY_LEN) + inner_nonce(8) + inner_ct */
        #ifndef PQ_AUTH_ENTRY_LEN
        #define PQ_AUTH_ENTRY_LEN (MOOR_KEM_CT_LEN + 32 + MOOR_PQ_SEAL_AEAD_TAG)
        #endif
        if (outer_pt_len < 2) { return -1; }
        uint8_t num_entries = outer_pt[1];
        if ((size_t)num_entries * PQ_AUTH_ENTRY_LEN + 2 > outer_pt_len) {
            LOG_ERROR("HS auth: num_entries %u exceeds descriptor length", num_entries);
            return -1;
        }
        size_t header_len = 2 + (size_t)num_entries * PQ_AUTH_ENTRY_LEN + 8;
        if (outer_pt_len < header_len + 16) {
            LOG_ERROR("HS auth: superencrypted descriptor too short");
            return -1;
        }

        int auth_ok = 0;
        uint8_t inner_key[32];
        extern moor_config_t g_config;
        if (g_config.client_auth_dir[0] != '\0') {
            char auth_path[512];
            snprintf(auth_path, sizeof(auth_path), "%s/%.*s.auth_private",
                     g_config.client_auth_dir, (int)(addr_len - 5), moor_address);
            FILE *af = fopen(auth_path, "rb");
            if (af) {
                /* PQ .auth_private format: kem_sk(MOOR_KEM_SK_LEN=2400) */
                uint8_t *client_kem_sk = malloc(MOOR_KEM_SK_LEN);
                if (client_kem_sk) {
                    if (fread(client_kem_sk, 1, MOOR_KEM_SK_LEN, af) == MOOR_KEM_SK_LEN) {
                        for (int i = 0; i < num_entries; i++) {
                            if (moor_crypto_pq_seal_open(
                                    inner_key,
                                    outer_pt + 2 + (size_t)i * PQ_AUTH_ENTRY_LEN,
                                    PQ_AUTH_ENTRY_LEN,
                                    client_kem_sk) == 0) {
                                auth_ok = 1;
                                LOG_INFO("HS auth: decrypted inner key (entry %d)", i);
                                break;
                            }
                        }
                    }
                    sodium_memzero(client_kem_sk, MOOR_KEM_SK_LEN);
                    free(client_kem_sk);
                }
                fclose(af);
            }
        }
        if (!auth_ok) {
            LOG_ERROR("HS auth: not authorized (cannot decrypt superencrypted descriptor)");
            return -1;
        }

        /* Decrypt inner layer with recovered inner_key */
        size_t nonce_off = 2 + (size_t)num_entries * PQ_AUTH_ENTRY_LEN;
        uint64_t inner_nonce = 0;
        for (int i = 7; i >= 0; i--)
            inner_nonce |= (uint64_t)outer_pt[nonce_off + (7 - i)] << (i * 8);

        const uint8_t *inner_ct = outer_pt + nonce_off + 8;
        size_t inner_ct_len = outer_pt_len - nonce_off - 8;
        uint8_t inner_pt[MOOR_DHT_MAX_DESC_DATA];
        size_t inner_pt_len;
        const uint8_t inner_ad[] = "moor-hs-auth";
        if (moor_crypto_aead_decrypt(inner_pt, &inner_pt_len,
                                      inner_ct, inner_ct_len,
                                      inner_ad, 12,
                                      inner_key, inner_nonce) != 0) {
            LOG_ERROR("HS auth: inner AEAD decryption failed");
            moor_crypto_wipe(inner_key, 32);
            return -1;
        }
        moor_crypto_wipe(inner_key, 32);

        if (moor_hs_descriptor_deserialize(&hs_desc, inner_pt, inner_pt_len) <= 0) {
            LOG_ERROR("HS auth: inner descriptor deserialization failed");
            sodium_memzero(inner_pt, sizeof(inner_pt));
            return -1;
        }
        sodium_memzero(inner_pt, sizeof(inner_pt));
        LOG_INFO("HS: superencrypted descriptor decrypted successfully");
    } else {
        /* No superencryption (public HS or legacy auth_type 1) — deserialize directly */
        if (moor_hs_descriptor_deserialize(&hs_desc, outer_pt, outer_pt_len) <= 0) {
            LOG_ERROR("HS: descriptor deserialization failed");
            return -1;
        }
    }

verify_descriptor:
    /* Verify the descriptor's service_pk matches what we expect */
    if (sodium_memcmp(hs_desc.service_pk, service_pk, 32) != 0) {
        LOG_ERROR("HS: descriptor service_pk mismatch (tampered?)");
        return -1;
    }

    /* Verify descriptor signature over address_hash + service_pk + content_hash.
     * Content hash covers blinded_pk, intro_points, pow_seed, pow_difficulty. */
    {
        uint8_t extra_buf[32 + 4 + MOOR_MAX_INTRO_POINTS * 32 + 32 + 1 + 8];
        size_t epos = 0;
        memcpy(extra_buf + epos, hs_desc.blinded_pk, 32); epos += 32;
        uint32_t nip = hs_desc.num_intro_points;
        memcpy(extra_buf + epos, &nip, 4); epos += 4;
        for (uint32_t ip = 0; ip < nip && ip < MOOR_MAX_INTRO_POINTS; ip++) {
            memcpy(extra_buf + epos, hs_desc.intro_points[ip].node_id, 32);
            epos += 32;
        }
        memcpy(extra_buf + epos, hs_desc.pow_seed, 32); epos += 32;
        extra_buf[epos++] = hs_desc.pow_difficulty;
        /* Revision counter must match what was signed */
        extra_buf[epos++] = (uint8_t)(hs_desc.revision >> 56);
        extra_buf[epos++] = (uint8_t)(hs_desc.revision >> 48);
        extra_buf[epos++] = (uint8_t)(hs_desc.revision >> 40);
        extra_buf[epos++] = (uint8_t)(hs_desc.revision >> 32);
        extra_buf[epos++] = (uint8_t)(hs_desc.revision >> 24);
        extra_buf[epos++] = (uint8_t)(hs_desc.revision >> 16);
        extra_buf[epos++] = (uint8_t)(hs_desc.revision >> 8);
        extra_buf[epos++] = (uint8_t)(hs_desc.revision);
        uint8_t content_hash[32];
        moor_crypto_hash(content_hash, extra_buf, epos);

        uint8_t to_verify[96];
        memcpy(to_verify, hs_desc.address_hash, 32);
        memcpy(to_verify + 32, hs_desc.service_pk, 32);
        memcpy(to_verify + 64, content_hash, 32);
        if (moor_crypto_sign_verify(hs_desc.signature, to_verify, 96,
                                     hs_desc.service_pk) != 0) {
            LOG_ERROR("HS: descriptor signature verification failed");
            return -1;
        }
        LOG_DEBUG("HS: descriptor signature verified");
    }

    /* Verify PQ commitment: the .moor address binds H(kem_pk || falcon_pk).
     * Recompute from descriptor pks and reject any mismatch. Prevents
     * service impersonation even if Ed25519 is broken (v3 binds Falcon pk
     * too; v2 addresses produced by older services only commit to kem_pk). */
    if (has_pq_commitment && hs_desc.kem_available) {
        uint8_t commit_buf[1184 + MOOR_FALCON_PK_LEN];
        size_t commit_len = 0;
        memcpy(commit_buf, hs_desc.kem_pk, sizeof(hs_desc.kem_pk));
        commit_len = sizeof(hs_desc.kem_pk);
        if (hs_desc.falcon_available) {
            memcpy(commit_buf + commit_len, hs_desc.falcon_pk,
                   sizeof(hs_desc.falcon_pk));
            commit_len += sizeof(hs_desc.falcon_pk);
        }
        uint8_t full_hash[32];
        moor_crypto_hash(full_hash, commit_buf, commit_len);
        if (sodium_memcmp(full_hash, pq_commitment, 16) == 0) {
            LOG_DEBUG("HS: PQ commitment verified (%s)",
                      hs_desc.falcon_available ? "v3 kem||falcon" : "v2 kem-only");
        } else if (hs_desc.falcon_available) {
            /* Try v2 fallback (kem-only) in case the service still publishes
             * a v2 address while also including falcon_pk for forward-compat. */
            moor_crypto_hash(full_hash, hs_desc.kem_pk, sizeof(hs_desc.kem_pk));
            if (sodium_memcmp(full_hash, pq_commitment, 16) != 0) {
                LOG_ERROR("HS: PQ commitment mismatch — descriptor pks don't match address");
                return -1;
            }
            LOG_DEBUG("HS: PQ commitment verified (v2 kem-only, service advertises Falcon)");
        } else {
            LOG_ERROR("HS: PQ commitment mismatch — KEM pk doesn't match address");
            return -1;
        }
    } else if (has_pq_commitment && !hs_desc.kem_available) {
        LOG_WARN("HS: address has PQ commitment but descriptor has no KEM pk");
    }

    /* Legacy client auth (auth_type 1): only onion_pk is sealed per client.
     * Kept for backward compatibility with older descriptors. */
    if (hs_desc.auth_type == 1) {
        int auth_ok = 0;
        extern moor_config_t g_config;
        if (g_config.client_auth_dir[0] != '\0') {
            char auth_path[512];
            snprintf(auth_path, sizeof(auth_path), "%s/%.*s.auth_private",
                     g_config.client_auth_dir, (int)(addr_len - 5), moor_address);
            FILE *af = fopen(auth_path, "rb");
            if (af) {
                uint8_t client_sk[32], client_pk[32];
                if (fread(client_sk, 1, 32, af) == 32) {
                    if (fread(client_pk, 1, 32, af) != 32)
                        crypto_scalarmult_base(client_pk, client_sk);
                    for (int i = 0; i < hs_desc.num_auth_entries; i++) {
                        uint8_t decrypted_pk[32];
                        if (moor_crypto_seal_open(decrypted_pk,
                                                    hs_desc.auth_entries[i], 80,
                                                    client_pk, client_sk) == 0) {
                            memcpy(hs_desc.onion_pk, decrypted_pk, 32);
                            moor_crypto_wipe(decrypted_pk, 32);
                            auth_ok = 1;
                            break;
                        }
                    }
                }
                moor_crypto_wipe(client_sk, 32);
                fclose(af);
            }
        }
        if (!auth_ok) {
            LOG_ERROR("HS auth: not authorized (legacy auth_type 1)");
            return -1;
        }
    }

    /* Build circuit to a rendezvous point */
    moor_circuit_t *rp_circ = moor_circuit_alloc();
    if (!rp_circ) return -1;

    moor_connection_t *rp_conn = moor_connection_alloc();
    if (!rp_conn) { moor_circuit_free(rp_circ); return -1; }

    /* skip_guard_reuse=1: HS RP circuit MUST use its own guard connection,
     * not the shared channel used by clearnet circuits.  Without this,
     * the synchronous HS connect blocks the event loop for ~8s while
     * Firefox's concurrent clearnet traffic starves on the shared guard,
     * the guard closes the stalled connection (EPIPE), and everything dies. */
    if (moor_circuit_build(rp_circ, rp_conn, consensus, our_pk, our_sk, 1) != 0) {
        moor_circuit_free(rp_circ);
        /* Close (not just free) if connection was actually opened (#126) */
        if (rp_conn->fd >= 0)
            moor_connection_close(rp_conn);
        else
            moor_connection_free(rp_conn);
        return -1;
    }
    rp_circ->cc_path_type = MOOR_CC_PATH_ONION; /* HS path (6 hops end-to-end) */

    /* Output HS KEM pk for PQ e2e upgrade after RENDEZVOUS2 */
    if (hs_kem_pk_out && hs_kem_available_out && hs_desc.kem_available) {
        memcpy(hs_kem_pk_out, hs_desc.kem_pk, 1184);
        *hs_kem_available_out = 1;
    }

    /* Send RELAY_ESTABLISH_RENDEZVOUS with random cookie */
    uint8_t cookie[MOOR_RENDEZVOUS_COOKIE_LEN];
    moor_crypto_random(cookie, sizeof(cookie));

    moor_cell_t cell;
    moor_cell_relay(&cell, rp_circ->circuit_id, RELAY_ESTABLISH_RENDEZVOUS, 0,
                   cookie, sizeof(cookie));
    if (moor_circuit_encrypt_forward(rp_circ, &cell) != 0 ||
        moor_connection_send_cell(rp_circ->conn, &cell) != 0) {
        LOG_ERROR("HS: failed to send ESTABLISH_RENDEZVOUS");
        moor_circuit_free(rp_circ);
        moor_connection_close(rp_conn);
        return -1;
    }

    /* Wait synchronously for RENDEZVOUS_ESTABLISHED so the backward digest
     * is updated before the connection is shared with the async event loop.
     * Without this, cells for other multiplexed circuits on the same
     * connection can desynchronize the RP circuit's digest state. */
    {
        moor_cell_t rp_resp;
        int got_est = 0;
        for (int attempt = 0; attempt < 20 && !got_est; attempt++) {
            struct pollfd pfd = { rp_circ->conn->fd, POLLIN, 0 };
            if (poll(&pfd, 1, 1500) <= 0) continue;
            int rr = moor_connection_recv_cell(rp_circ->conn, &rp_resp);
            if (rr <= 0) continue;
            /* Dispatch cells for other circuits on multiplexed connection (#198) */
            if (rp_resp.circuit_id != rp_circ->circuit_id) {
                if (rp_circ->conn->on_other_cell)
                    rp_circ->conn->on_other_cell(rp_circ->conn, &rp_resp);
                continue;
            }
            if (moor_circuit_decrypt_backward(rp_circ, &rp_resp) != 0) continue;
            moor_relay_payload_t rp_relay;
            moor_relay_unpack(&rp_relay, rp_resp.payload);
            if (rp_relay.recognized == 0 &&
                rp_relay.relay_command == RELAY_RENDEZVOUS_ESTABLISHED) {
                LOG_DEBUG("HS: RENDEZVOUS_ESTABLISHED received (sync)");
                got_est = 1;
            }
        }
        if (!got_est) {
            LOG_ERROR("HS: timeout waiting for RENDEZVOUS_ESTABLISHED");
            moor_circuit_free(rp_circ);
            moor_connection_close(rp_conn);
            return -1;
        }
    }

    /* Build circuit to intro point -- last hop MUST be the intro relay */
    if (hs_desc.num_intro_points == 0) {
        LOG_ERROR("HS has no intro points");
        moor_circuit_free(rp_circ);
        moor_connection_close(rp_conn);
        return -1;
    }

    moor_circuit_t *intro_circ = moor_circuit_alloc();
    if (!intro_circ) {
        moor_circuit_free(rp_circ);
        moor_connection_close(rp_conn);
        return -1;
    }

    moor_connection_t *intro_conn = moor_connection_alloc();
    if (!intro_conn) {
        moor_circuit_free(intro_circ);
        moor_circuit_free(rp_circ);
        moor_connection_close(rp_conn);
        return -1;
    }

    /* Build a candidate list: shuffle all intro indices, then filter out
     * ones in the failure cache.  If every intro is blacklisted (they've all
     * recently failed), clear this service's cache entries and try them all
     * anyway — descriptor might be freshly rotated and the old failures stale.
     *
     * Randomization matters: before this we always tried index 0 first, so if
     * intro 0 went silently stale every client hammered it forever while 1
     * and 2 sat idle. */
    uint32_t num_intros = hs_desc.num_intro_points;
    uint32_t order[MOOR_MAX_INTRO_POINTS];
    for (uint32_t i = 0; i < num_intros; i++) order[i] = i;
    /* Fisher-Yates shuffle */
    for (uint32_t i = num_intros; i > 1; i--) {
        uint32_t j = randombytes_uniform(i);
        uint32_t t = order[i - 1]; order[i - 1] = order[j]; order[j] = t;
    }

    uint32_t candidates[MOOR_MAX_INTRO_POINTS];
    uint32_t num_candidates = 0;
    for (uint32_t i = 0; i < num_intros; i++) {
        uint32_t ip = order[i];
        if (moor_hs_intro_is_failed(service_pk,
                                     hs_desc.intro_points[ip].node_id)) {
            LOG_DEBUG("HS: skipping intro %u (in failure cache)", ip);
            continue;
        }
        candidates[num_candidates++] = ip;
    }
    if (num_candidates == 0) {
        LOG_WARN("HS: all %u intro points blacklisted — clearing cache for retry",
                 num_intros);
        moor_hs_intro_clear_failures_for(service_pk);
        for (uint32_t i = 0; i < num_intros; i++)
            candidates[num_candidates++] = order[i];
    }

    /* Try candidates in shuffled order until one builds. */
    int intro_built = 0;
    uint32_t picked_ip = 0;
    for (uint32_t ci = 0; ci < num_candidates && !intro_built; ci++) {
        uint32_t ip = candidates[ci];
        if (moor_hs_build_circuit_to_rp(intro_circ, intro_conn, consensus,
                                          NULL, our_pk, our_sk,
                                          hs_desc.intro_points[ip].node_id) == 0) {
            intro_built = 1;
            picked_ip = ip;
            LOG_INFO("HS: intro circuit built to intro point %u (%u candidates)",
                     ip, num_candidates);
        } else {
            LOG_WARN("HS: failed to build circuit to intro point %u, trying next",
                     ip);
            /* Reset for next attempt -- free and reallocate both */
            moor_circuit_free(intro_circ);
            intro_circ = NULL;
            if (intro_conn->fd >= 0)
                close(intro_conn->fd);
            moor_connection_free(intro_conn);
            intro_conn = NULL;
            /* Re-allocate for next attempt */
            if (ci + 1 < num_candidates) {
                intro_circ = moor_circuit_alloc();
                if (!intro_circ) break;
                intro_conn = moor_connection_alloc();
                if (!intro_conn) { moor_circuit_free(intro_circ); intro_circ = NULL; break; }
            }
        }
    }
    if (intro_built && intro_node_id_out) {
        memcpy(intro_node_id_out,
               hs_desc.intro_points[picked_ip].node_id, 32);
    }
    if (!intro_built) {
        LOG_ERROR("HS: failed to build circuit to any intro point");
        moor_circuit_free(intro_circ);
        moor_circuit_free(rp_circ);
        if (rp_conn->fd >= 0)
            moor_connection_close(rp_conn);
        else
            moor_connection_free(rp_conn);
        if (intro_conn) {
            if (intro_conn->fd >= 0) close(intro_conn->fd);
            moor_connection_free(intro_conn);
        }
        return -1;
    }
    intro_circ->cc_path_type = MOOR_CC_PATH_ONION; /* 6-hop HS circuit */

    /* Generate ephemeral keypair for HS DH */
    uint8_t eph_pk[32], eph_sk[32];
    moor_crypto_box_keygen(eph_pk, eph_sk);

    /* PQ migration: descriptor must carry an ML-KEM pk -- we seal
     * INTRODUCE1 to that key now, not the classical onion_pk. */
    if (!hs_desc.kem_available) {
        LOG_ERROR("HS: descriptor has no KEM pk (PQ-sealed INTRODUCE1 required)");
        moor_crypto_wipe(eph_sk, 32);
        moor_circuit_free(intro_circ);
        moor_connection_close(intro_conn);
        moor_circuit_free(rp_circ);
        moor_connection_close(rp_conn);
        return -1;
    }

    /* Build INTRODUCE1 plaintext:
     *   rp_node_id(32) + cookie(20) + client_eph_pk(32) = 84 bytes */
    uint8_t intro_plaintext[84];
    if (rp_circ->num_hops > 0) {
        memcpy(intro_plaintext,
               rp_circ->hops[rp_circ->num_hops - 1].node_id, 32);
    } else {
        memset(intro_plaintext, 0, 32);
    }
    memcpy(intro_plaintext + 32, cookie, 20);
    memcpy(intro_plaintext + 52, eph_pk, 32);

    /* PQ seal (ML-KEM-768 + ChaCha20-Poly1305) to service's KEM pk.
     * Intro point is blind: it can neither decrypt nor substitute. */
    uint8_t intro_sealed[84 + MOOR_PQ_SEAL_OVERHEAD];
    if (moor_crypto_pq_seal(intro_sealed, intro_plaintext, 84,
                             hs_desc.kem_pk) != 0) {
        LOG_ERROR("HS: failed to PQ-seal INTRODUCE1");
        moor_crypto_wipe(eph_sk, 32);
        moor_circuit_free(intro_circ);
        moor_connection_close(intro_conn);
        moor_circuit_free(rp_circ);
        moor_connection_close(rp_conn);
        return -1;
    }

    /* Build INTRODUCE1 payload:
     *   blinded_pk(32) + pow_flag(1) + [nonce(8) if pow] + pq_sealed
     * The blinded_pk prefix lets the intro relay route the cell to the
     * correct ESTABLISH_INTRO circuit when it serves multiple services.
     * Total ~1229B -- exceeds one cell, sent via moor_fragment_send. */
    uint8_t intro_payload[32 + 1 + 8 + 84 + MOOR_PQ_SEAL_OVERHEAD];
    size_t intro_payload_len = 0;

    memcpy(intro_payload, hs_desc.blinded_pk, 32);
    intro_payload_len = 32;

    if (hs_desc.pow_difficulty > 0) {
        uint64_t pow_nonce;
        if (moor_pow_solve_hs(&pow_nonce, hs_desc.pow_seed,
                               hs_desc.service_pk, hs_desc.pow_difficulty,
                               0) != 0) {
            LOG_ERROR("HS: PoW solve failed");
            moor_crypto_wipe(eph_sk, 32);
            moor_circuit_free(intro_circ);
            moor_connection_close(intro_conn);
            moor_circuit_free(rp_circ);
            moor_connection_close(rp_conn);
            return -1;
        }
        LOG_INFO("HS: PoW solved (difficulty %u)", hs_desc.pow_difficulty);
        intro_payload[32] = 0x01; /* pow_flag = 1 */
        for (int b = 7; b >= 0; b--)
            intro_payload[33 + (7 - b)] = (uint8_t)(pow_nonce >> (b * 8));
        memcpy(intro_payload + 41, intro_sealed, sizeof(intro_sealed));
        intro_payload_len = 41 + sizeof(intro_sealed);
    } else {
        intro_payload[32] = 0x00; /* pow_flag = 0 */
        memcpy(intro_payload + 33, intro_sealed, sizeof(intro_sealed));
        intro_payload_len = 33 + sizeof(intro_sealed);
    }

    /* Send INTRODUCE1 via fragmentation (single cell if it fits,
     * otherwise RELAY_FRAGMENT/RELAY_FRAGMENT_END with inner_cmd=INTRODUCE1). */
    if (moor_fragment_send(intro_circ->circuit_id, RELAY_INTRODUCE1, 0,
                            intro_payload, intro_payload_len,
                            moor_fragment_gen_id(),
                            hs_client_intro_send_cb, intro_circ) != 0) {
        LOG_ERROR("HS: failed to send INTRODUCE1 (fragmented)");
        moor_crypto_wipe(eph_sk, 32);
        moor_circuit_destroy(intro_circ);
        moor_connection_close(intro_conn);
        moor_circuit_free(rp_circ);
        moor_connection_close(rp_conn);
        return -1;
    }

    LOG_INFO("HS: sealed INTRODUCE1 sent (async, returning RP circuit)");

    /* Clean up intro circuit (no longer needed) */
    moor_circuit_destroy(intro_circ);
    moor_connection_close(intro_conn);

    /* Store eph_sk on RP circuit for DH completion after RENDEZVOUS2 (#197) */
    memcpy(rp_circ->e2e_eph_sk, eph_sk, 32);
    moor_crypto_wipe(eph_sk, 32);  /* Wipe stack copy, circuit has it */
    *rp_circuit_out = rp_circ;
    return 0;
}

int moor_hs_client_connect(const char *moor_address,
                           moor_circuit_t **circuit_out,
                           const moor_consensus_t *consensus,
                           const char *da_address, uint16_t da_port,
                           const uint8_t our_pk[32],
                           const uint8_t our_sk[64]) {
    moor_circuit_t *rp_circ = NULL;
    if (moor_hs_client_connect_start(moor_address, &rp_circ,
                                      consensus, da_address, da_port,
                                      our_pk, our_sk, NULL, NULL, NULL) != 0)
        return -1;

    /* Wait for RENDEZVOUS2 on the RP circuit (up to 60 seconds) */
    int got_rv2 = 0;
    int established_count = 0;
    for (int wait = 0; wait < 60 && !got_rv2; wait++) {
        if (hs_wait_for_readable(rp_circ->conn->fd, 1000) <= 0)
            continue;

        moor_cell_t rv2_cell;
        int ret = moor_connection_recv_cell(rp_circ->conn, &rv2_cell);
        if (ret <= 0) continue;

        /* Dispatch cells for other circuits on multiplexed connection (#198) */
        if (rv2_cell.circuit_id != rp_circ->circuit_id) {
            if (rp_circ->conn->on_other_cell)
                rp_circ->conn->on_other_cell(rp_circ->conn, &rv2_cell);
            continue;
        }

        if (moor_circuit_decrypt_backward(rp_circ, &rv2_cell) != 0) {
            LOG_WARN("HS: backward decrypt failed waiting for RENDEZVOUS2");
            continue;
        }

        moor_relay_payload_t rv2_relay;
        moor_relay_unpack(&rv2_relay, rv2_cell.payload);

        if (rv2_relay.recognized == 0) {
            if (rv2_relay.relay_command == RELAY_RENDEZVOUS2) {
                LOG_INFO("HS: RENDEZVOUS2 received (%u bytes)",
                         rv2_relay.data_length);
                /* Complete e2e DH key exchange (#197) */
                if (rv2_relay.data_length >= 64) {
                    uint8_t *hs_eph_pk = rv2_relay.data;
                    uint8_t *hs_key_hash = rv2_relay.data + 32;
                    uint8_t shared[32];
                    if (moor_crypto_dh(shared, rp_circ->e2e_eph_sk,
                                       hs_eph_pk) != 0) {
                        LOG_ERROR("HS: e2e DH failed");
                        moor_crypto_wipe(shared, 32);
                    } else {
                        uint8_t expected_hash[32];
                        moor_crypto_hash(expected_hash, shared, 32);
                        if (sodium_memcmp(expected_hash, hs_key_hash, 32) != 0) {
                            LOG_ERROR("HS: e2e key_hash mismatch");
                            moor_crypto_wipe(shared, 32);
                        } else {
                            /* Client: send=subkey 0, recv=subkey 1 */
                            moor_crypto_kdf(rp_circ->e2e_send_key, 32,
                                            shared, 0, "moore2e!");
                            moor_crypto_kdf(rp_circ->e2e_recv_key, 32,
                                            shared, 1, "moore2e!");
                            rp_circ->e2e_send_nonce = 0;
                            rp_circ->e2e_recv_nonce = 0;
                            rp_circ->e2e_active = 1;
                            LOG_INFO("HS: e2e encryption established");
                            moor_crypto_wipe(shared, 32);
                        }
                    }
                }
                moor_crypto_wipe(rp_circ->e2e_eph_sk, 32);
                got_rv2 = 1;
            } else if (rv2_relay.relay_command ==
                       RELAY_RENDEZVOUS_ESTABLISHED) {
                LOG_DEBUG("HS: RENDEZVOUS_ESTABLISHED (informational)");
                if (established_count++ < 1)
                    wait--; /* Don't count first one as a timeout tick */
            }
        }
    }

    if (!got_rv2) {
        LOG_ERROR("HS: timeout waiting for RENDEZVOUS2");
        moor_circuit_destroy(rp_circ);
        return -1;
    }

    *circuit_out = rp_circ;
    return 0;
}

/* ================================================================
 * Dynamic intro point rotation
 * ================================================================ */
int moor_hs_check_intro_rotation(moor_hs_config_t *config,
                                  const moor_consensus_t *consensus) {
    if (!config || !consensus) return 0;

    uint64_t now = (uint64_t)time(NULL);
    int rotated = 0;

    for (int i = 0; i < config->num_intro_circuits; i++) {
        int needs_rotate = 0;
        moor_circuit_t *circ = config->intro_circuits[i];

        /* Check liveness: intro circuits can die silently (relay-side DESTROY
         * not delivered, NAT black-hole, kernel-detected socket error that
         * never propagated to invalidate_circuit). Without this, a non-NULL
         * but dead circ pointer means the HS becomes permanently unreachable
         * because the rotation code below thinks the intro is healthy. */
        if (circ && (MOOR_CIRCUIT_IS_MARKED(circ) ||
                     !circ->conn ||
                     circ->conn->state != CONN_STATE_OPEN ||
                     circ->conn->fd < 0)) {
            LOG_INFO("HS: intro point %d circuit dead (marked=%u state=%d fd=%d), rotating",
                     i,
                     circ->marked_for_close,
                     circ->conn ? (int)circ->conn->state : -1,
                     circ->conn ? circ->conn->fd : -1);
            needs_rotate = 1;
        }

        /* Check age: rotate after MOOR_HS_INTRO_MAX_LIFETIME_SEC */
        if (config->intro_established_at[i] > 0 &&
            (now - config->intro_established_at[i]) >= MOOR_HS_INTRO_MAX_LIFETIME_SEC) {
            LOG_INFO("HS: intro point %d aged out (%llu sec), rotating",
                     i, (unsigned long long)(now - config->intro_established_at[i]));
            needs_rotate = 1;
        }

        /* Check count: rotate after MOOR_HS_INTRO_MAX_INTRODUCTIONS */
        if (config->intro_count[i] >= MOOR_HS_INTRO_MAX_INTRODUCTIONS) {
            LOG_INFO("HS: intro point %d hit max introductions (%u), rotating",
                     i, config->intro_count[i]);
            needs_rotate = 1;
        }

        if (needs_rotate && config->intro_circuits[i]) {
            /* Tear down old intro circuit */
            moor_circuit_destroy(config->intro_circuits[i]);
            config->intro_circuits[i] = NULL;
            config->intro_count[i] = 0;
            config->intro_established_at[i] = 0;
            rotated++;
        }
    }

    /* Re-establish any missing intro points — covers both rotation
     * (aged out / max count) AND dead circuits (connection lost).
     * Without this, intro circuits that die from network issues are
     * never re-established and the HS becomes permanently unreachable. */
    int missing = 0;
    for (int i = 0; i < config->num_intro_circuits; i++) {
        if (!config->intro_circuits[i])
            missing++;
    }
    if (rotated > 0 || missing > 0) {
        LOG_INFO("HS: %d rotated, %d dead — flagging for deferred re-establishment",
                 rotated, missing);
        /* Don't call moor_hs_establish_intro inline — the synchronous
         * circuit build reuses connection pool slots, corrupting live
         * intro circuits' connections. Set the flag and let the deferred
         * handler in hs_intro_rotation_cb rebuild them safely. */
        config->intros_need_reestablish = 1;
    }

    return rotated;
}

/* ---- V2 Address with checksum ---- */

int moor_hs_compute_address_v2(char *out, size_t out_len,
                                const uint8_t identity_pk[32]) {
    /* Format: base32(identity_pk(32) + checksum(2) + version(1)) + ".moor"
     * checksum = BLAKE2b(".moor checksum" || identity_pk || version)[0:2]
     * Total: 35 bytes → 56 chars base32 + ".moor\0" = 62 chars */
    uint8_t version = 0x03; /* v3 format */

    /* Compute checksum */
    uint8_t cksum_input[14 + 32 + 1]; /* ".moor checksum" + pk + version */
    memcpy(cksum_input, ".moor checksum", 14);
    memcpy(cksum_input + 14, identity_pk, 32);
    cksum_input[46] = version;

    uint8_t full_hash[32];
    moor_crypto_hash(full_hash, cksum_input, 47);
    uint8_t checksum[2] = { full_hash[0], full_hash[1] };

    /* Build 35-byte payload */
    uint8_t payload[35];
    memcpy(payload, identity_pk, 32);
    payload[32] = checksum[0];
    payload[33] = checksum[1];
    payload[34] = version;

    char b32[64];
    int b32_len = moor_base32_encode(b32, sizeof(b32), payload, 35);
    if (b32_len < 0) return -1;

    if ((size_t)b32_len + 6 > out_len) return -1;
    memcpy(out, b32, b32_len);
    memcpy(out + b32_len, ".moor", 6);
    return 0;
}

int moor_hs_decode_address(uint8_t identity_pk[32], const char *address) {
    if (!address) return -1;

    /* Strip ".moor" suffix */
    size_t alen = strlen(address);
    if (alen < 6) return -1;
    if (strcmp(address + alen - 5, ".moor") != 0) return -1;

    char b32[128];
    size_t b32_len = alen - 5;
    if (b32_len >= sizeof(b32)) return -1;
    memcpy(b32, address, b32_len);
    b32[b32_len] = '\0';

    uint8_t decoded[64];
    int decoded_len = moor_base32_decode(decoded, sizeof(decoded), b32, b32_len);

    if (decoded_len == 48 || decoded_len == 32) {
        /* v3: 32 identity_pk + 16 BLAKE2b_16(kem_pk||falcon_pk)
         * v1: 32 identity_pk (legacy, no PQ commit)
         * PQ commit verification happens in moor_hs_client_connect_start
         * against the fetched descriptor; this decoder only extracts the pk. */
        memcpy(identity_pk, decoded, 32);
        return 0;
    } else if (decoded_len == 35) {
        /* v2 format with checksum (pre-PQ commit) */
        memcpy(identity_pk, decoded, 32);
        uint8_t cksum_input[14 + 32 + 1];
        memcpy(cksum_input, ".moor checksum", 14);
        memcpy(cksum_input + 14, identity_pk, 32);
        cksum_input[46] = decoded[34];

        uint8_t full_hash[32];
        moor_crypto_hash(full_hash, cksum_input, 47);
        if (full_hash[0] != decoded[32] || full_hash[1] != decoded[33]) {
            LOG_WARN("HS address checksum mismatch");
            return -1;
        }
        return 0;
    }
    return -1;
}

/* ---- Authorized client persistence ---- */

int moor_hs_save_auth_clients(const moor_hs_config_t *config) {
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/clients", config->hs_dir);
    mkdir(dir, 0700);

    for (int i = 0; i < config->num_auth_clients; i++) {
        char path[576];
        snprintf(path, sizeof(path), "%s/client_%d.kem_pk", dir, i);
        FILE *f = fopen(path, "wb");
        if (!f) continue;
        fwrite(config->auth_clients[i].kem_pk, 1,
               sizeof(config->auth_clients[i].kem_pk), f);
        fclose(f);
    }

    /* Write count file */
    char path[576];
    snprintf(path, sizeof(path), "%s/count", dir);
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "%d\n", config->num_auth_clients);
        fclose(f);
    }

    LOG_INFO("HS: saved %d auth clients (ML-KEM pks)", config->num_auth_clients);
    return 0;
}

int moor_hs_load_auth_clients(moor_hs_config_t *config) {
    char path[512];
    snprintf(path, sizeof(path), "%s/clients/count", config->hs_dir);
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    int count = 0;
    if (fscanf(f, "%d", &count) != 1) { fclose(f); return -1; }
    fclose(f);

    if (count > MOOR_MAX_AUTH_CLIENTS) count = MOOR_MAX_AUTH_CLIENTS;

    config->num_auth_clients = 0;
    for (int i = 0; i < count; i++) {
        snprintf(path, sizeof(path), "%s/clients/client_%d.kem_pk",
                 config->hs_dir, i);
        f = fopen(path, "rb");
        if (!f) continue;
        uint8_t *slot = config->auth_clients[config->num_auth_clients].kem_pk;
        size_t want = sizeof(config->auth_clients[0].kem_pk);
        if (fread(slot, 1, want, f) == want)
            config->num_auth_clients++;
        fclose(f);
    }

    LOG_INFO("HS: loaded %d auth clients (ML-KEM pks)", config->num_auth_clients);
    return 0;
}

/* ---- PoW seed persistence ---- */

int moor_hs_save_pow_seed(const moor_hs_config_t *config) {
    char path[512];
    snprintf(path, sizeof(path), "%s/pow_seed", config->hs_dir);
    FILE *f = secure_fopen(path, "wb");
    if (!f) return -1;
    fwrite(config->pow_seed, 1, 32, f);
    fclose(f);
    return 0;
}

int moor_hs_load_pow_seed(moor_hs_config_t *config) {
    char path[512];
    snprintf(path, sizeof(path), "%s/pow_seed", config->hs_dir);
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fread(config->pow_seed, 1, 32, f) != 32) {
        fclose(f);
        return -1;
    }
    fclose(f);
    LOG_INFO("HS: loaded PoW seed from disk");
    return 0;
}

/* ---- Descriptor revision counter persistence ---- */

int moor_hs_save_revision(const moor_hs_config_t *config) {
    char path[512];
    snprintf(path, sizeof(path), "%s/revision", config->hs_dir);
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    uint8_t buf[8];
    for (int i = 7; i >= 0; i--)
        buf[7 - i] = (uint8_t)(config->desc_revision >> (i * 8));
    fwrite(buf, 1, 8, f);
    fclose(f);
    return 0;
}

int moor_hs_load_revision(moor_hs_config_t *config) {
    char path[512];
    snprintf(path, sizeof(path), "%s/revision", config->hs_dir);
    FILE *f = fopen(path, "rb");
    if (!f) { config->desc_revision = 0; return -1; }
    uint8_t buf[8];
    if (fread(buf, 1, 8, f) != 8) { fclose(f); return -1; }
    fclose(f);
    config->desc_revision = 0;
    for (int i = 0; i < 8; i++)
        config->desc_revision |= (uint64_t)buf[i] << ((7 - i) * 8);
    LOG_INFO("HS: loaded revision counter: %llu",
             (unsigned long long)config->desc_revision);
    return 0;
}

/* ---- Pointer invalidation (called from circ_free_unlocked / conn_free) ---- */

extern moor_hs_config_t *g_hs_configs;
extern int g_num_hs_configs;

void moor_hs_invalidate_circuit(moor_circuit_t *circ) {
    if (!circ || !g_hs_configs) return;

    for (int h = 0; h < g_num_hs_configs; h++) {
        moor_hs_config_t *cfg = &g_hs_configs[h];
        for (int i = 0; i < MOOR_MAX_INTRO_POINTS; i++) {
            if (cfg->intro_circuits[i] == circ)
                cfg->intro_circuits[i] = NULL;
        }
        for (int i = 0; i < 8; i++) {
            if (cfg->rp_circuits[i] == circ) {
                cfg->rp_circuits[i] = NULL;
                cfg->rp_connections[i] = NULL;
            }
        }
    }
}

void moor_hs_nullify_conn(moor_connection_t *conn) {
    if (!conn || !g_hs_configs) return;

    for (int h = 0; h < g_num_hs_configs; h++) {
        moor_hs_config_t *cfg = &g_hs_configs[h];
        for (int i = 0; i < 8; i++) {
            if (cfg->rp_connections[i] == conn)
                cfg->rp_connections[i] = NULL;
        }
    }
}
