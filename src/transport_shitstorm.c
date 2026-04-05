/*
 * MOOR -- ShitStorm Transport
 *
 * Layered defense combining the strongest features of Mirage, Shade,
 * and Scramble into a single transport with defense-in-depth:
 *
 *   OUTER LAYER (from Mirage):
 *     TLS 1.3 record framing on the wire.  ClientHello with real x25519
 *     key_share, random SNI from CDN pool, session_id = HMAC(node_id,
 *     client_random) for active probing resistance, fake encrypted
 *     handshake records (4 records, 2000-4000 bytes), first-record
 *     padding to 1400-1500 bytes.
 *
 *   KEY GENERATION (from Shade + Elligator2):
 *     Constant-time key generation from a pre-computed pool of 32
 *     Elligator2-representable x25519 keypairs.  The key_share bytes
 *     on the wire are Elligator2 representatives -- indistinguishable
 *     from 32 uniform random bytes.  The peer recovers the real
 *     Curve25519 public key via the Elligator2 direct map.
 *
 *   KEY DERIVATION (from Scramble):
 *     Double-DH: DH(eph, eph) + DH(eph, identity) mixed via HKDF with
 *     transcript hash.  Inner keys derived from outer key material.
 *
 *   INNER LAYER (from Scramble):
 *     Inside each TLS Application Data record: ChaCha20-Poly1305 encrypted
 *     outer payload, whose plaintext is [2-byte XOR-obfuscated length] +
 *     [inner ChaCha20-Poly1305 encrypted payload].  Inner plaintext:
 *     [data] + [0-15 bytes random pad] + [1 byte pad_len].
 *
 *   REPLAY DEFENSE (from Shade):
 *     256-entry replay cache with 600s TTL on server side rejects
 *     replayed client ephemeral keys.
 *
 * Handshake flow:
 *   CLIENT:
 *     1. Generate Elligator2-representable x25519 keypair (from pool)
 *     2. Build TLS 1.3 ClientHello with key_share, random SNI,
 *        session_id = HMAC(node_id, client_random)
 *     3. Send ClientHello
 *     4. Receive ServerHello + CCS + fake encrypted HS records
 *     5. Derive outer keys: HKDF(DH(eph,eph) + DH(eph,identity) + transcript)
 *     6. Derive inner keys: KDF(outer_material, "shtstm!", subkeys 0-3)
 *     7. Send client Finished inside TLS app data record
 *
 *   SERVER:
 *     1. Receive ClientHello, verify session_id HMAC
 *     2. Check replay cache
 *     3. Generate Elligator2-representable server keypair
 *     4. Send ServerHello + CCS + fake encrypted HS records
 *     5. Derive outer + inner keys (same derivation)
 *     6. Receive and verify client Finished
 *
 *   POST-HANDSHAKE:
 *     TLS Application Data record wraps:
 *       OUTER AEAD(outer_key): [obfuscated_len:2][INNER AEAD(inner_key): [data][pad][pad_len]]
 */
#include "moor/moor.h"
#include "moor/transport_shitstorm.h"
#include "moor/elligator2.h"
#include <sodium.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define MSG_NOSIGNAL 0
#else
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#endif

/* ================================================================
 * TLS record constants (same as Mirage)
 * ================================================================ */
#define TLS_CHANGE_CIPHER_SPEC  20
#define TLS_HANDSHAKE           22
#define TLS_APPLICATION_DATA    23
#define TLS_HS_CLIENT_HELLO     1
#define TLS_HS_SERVER_HELLO     2
#define TLS_VERSION_12          0x0303
#define TLS_VERSION_13          0x0304
#define TLS_MAX_FRAGMENT        16384
#define TLS_RECORD_HEADER       5
#define TLS_AES_128_GCM_SHA256        0x1301
#define TLS_AES_256_GCM_SHA384        0x1302
#define TLS_CHACHA20_POLY1305_SHA256  0x1303

/* Finished message magic (client proves it holds derived keys) */
#define SHITSTORM_FINISHED_MAGIC_LEN  16
static const uint8_t SHITSTORM_FINISHED_MAGIC[16] = {
    0x53, 0x48, 0x49, 0x54, 0x53, 0x54, 0x4F, 0x52,  /* "SHITSTOR" */
    0x4D, 0x46, 0x49, 0x4E, 0x00, 0x00, 0x00, 0x01    /* "MFIN" + version */
};

/* ================================================================
 * x25519 key generation pool
 *
 * Pre-generate a pool of x25519 keypairs so that drawing a key is
 * constant-time (no timing leak reveals keygen iteration count).
 *
 * Elligator2 key generation: each keypair in the pool is generated
 * via moor_elligator2_keygen(), which rejection-samples until the
 * public key is Elligator2-representable, then computes the uniform
 * representative.  The key_share bytes placed on the wire are the
 * representative (indistinguishable from 32 random bytes), NOT the
 * raw Curve25519 point.  The peer recovers the real public key via
 * moor_elligator2_representative_to_key() before performing DH.
 * ================================================================ */
#define SS_KEY_POOL_SIZE    32

typedef struct {
    uint8_t pk[32];             /* Curve25519 public key */
    uint8_t sk[32];             /* Curve25519 secret key */
    uint8_t representative[32]; /* Elligator2 representative (wire bytes) */
} ss_keypair_t;

static ss_keypair_t g_ss_key_pool[SS_KEY_POOL_SIZE];
static int g_ss_pool_count = 0;
static int g_ss_pool_initialized = 0;
#ifndef _WIN32
static pthread_mutex_t g_ss_pool_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

static void ss_pool_fill(void) {
    /* Caller must hold g_ss_pool_mutex */
    while (g_ss_pool_count < SS_KEY_POOL_SIZE) {
        moor_elligator2_keygen(g_ss_key_pool[g_ss_pool_count].pk,
                               g_ss_key_pool[g_ss_pool_count].sk,
                               g_ss_key_pool[g_ss_pool_count].representative);
        g_ss_pool_count++;
    }
}

static void ss_pool_init(void) {
#ifndef _WIN32
    pthread_mutex_lock(&g_ss_pool_mutex);
#endif
    if (!g_ss_pool_initialized) {
        ss_pool_fill();
        g_ss_pool_initialized = 1;
    }
#ifndef _WIN32
    pthread_mutex_unlock(&g_ss_pool_mutex);
#endif
}

/* Draw keypair from pre-computed pool (constant-time draw).
 * Returns the Elligator2 representative in repr[32] (the wire bytes
 * to place in TLS key_share) and the real sk in sk[32]. */
static void ss_keygen_ct(uint8_t repr[32], uint8_t sk[32]) {
    ss_pool_init();

#ifndef _WIN32
    pthread_mutex_lock(&g_ss_pool_mutex);
#endif

    if (g_ss_pool_count > 0) {
        g_ss_pool_count--;
        memcpy(repr, g_ss_key_pool[g_ss_pool_count].representative, 32);
        memcpy(sk,   g_ss_key_pool[g_ss_pool_count].sk, 32);
        sodium_memzero(&g_ss_key_pool[g_ss_pool_count], sizeof(ss_keypair_t));
        if (g_ss_pool_count < SS_KEY_POOL_SIZE / 2)
            ss_pool_fill();
#ifndef _WIN32
        pthread_mutex_unlock(&g_ss_pool_mutex);
#endif
        return;
    }

#ifndef _WIN32
    pthread_mutex_unlock(&g_ss_pool_mutex);
#endif

    /* Pool exhausted: generate directly (no pool access needed) */
    uint8_t pk_tmp[32];
    moor_elligator2_keygen(pk_tmp, sk, repr);
    sodium_memzero(pk_tmp, 32);
}

/* ================================================================
 * Replay cache (from Shade: 256 entries, 600s TTL)
 * Uses hash-based slot placement (BLAKE2b of ephemeral key) with
 * linear probing instead of FIFO, so an attacker cannot evict a
 * specific entry by flooding the cache with connections.
 * ================================================================ */
#define SS_REPLAY_CACHE_SIZE 4096   /* was 256: resist cache exhaustion attacks */
#define SS_REPLAY_TTL_SECS   600

static struct {
    uint8_t  pk[32];
    uint64_t timestamp;
} g_ss_replay_cache[SS_REPLAY_CACHE_SIZE];

static pthread_mutex_t g_ss_replay_mutex = PTHREAD_MUTEX_INITIALIZER;

static int ss_replay_check(const uint8_t pk[32]) {
    pthread_mutex_lock(&g_ss_replay_mutex);
    uint64_t now = (uint64_t)time(NULL);

    /* Use BLAKE2b hash of the ephemeral key to determine slot.
     * This prevents an attacker from evicting a specific entry
     * by flooding the cache with 256 connections (the old FIFO
     * allowed targeted eviction). */
    uint8_t slot_hash[4];
    crypto_generichash_blake2b(slot_hash, sizeof(slot_hash), pk, 32,
                               (const unsigned char *)"ss-replay", 9);
    uint32_t slot = ((uint32_t)slot_hash[0] << 8 | (uint32_t)slot_hash[1])
                    % SS_REPLAY_CACHE_SIZE;

    /* Linear probing: find matching, expired, or empty slot */
    for (int probe = 0; probe < SS_REPLAY_CACHE_SIZE; probe++) {
        int idx = (int)((slot + (uint32_t)probe) % SS_REPLAY_CACHE_SIZE);
        if (!g_ss_replay_cache[idx].timestamp ||
            now - g_ss_replay_cache[idx].timestamp >= SS_REPLAY_TTL_SECS) {
            /* Empty or expired slot -- use it */
            memcpy(g_ss_replay_cache[idx].pk, pk, 32);
            g_ss_replay_cache[idx].timestamp = now;
            pthread_mutex_unlock(&g_ss_replay_mutex);
            return 0; /* not a replay */
        }
        if (sodium_memcmp(g_ss_replay_cache[idx].pk, pk, 32) == 0) {
            pthread_mutex_unlock(&g_ss_replay_mutex);
            return -1; /* REPLAY DETECTED */
        }
    }
    /* Cache full -- evict oldest entry to prevent legitimate client lockout.
     * An attacker who can fill the cache already has the ability to connect,
     * so eviction doesn't weaken replay protection in practice. */
    int oldest_idx = (int)slot;
    uint64_t oldest_ts = UINT64_MAX;
    for (int i = 0; i < SS_REPLAY_CACHE_SIZE; i++) {
        if (g_ss_replay_cache[i].timestamp < oldest_ts) {
            oldest_ts = g_ss_replay_cache[i].timestamp;
            oldest_idx = i;
        }
    }
    memcpy(g_ss_replay_cache[oldest_idx].pk, pk, 32);
    g_ss_replay_cache[oldest_idx].timestamp = now;
    pthread_mutex_unlock(&g_ss_replay_mutex);
    return 0;
}

/* ================================================================
 * SNI pool (same as Mirage, with local CDN discovery override)
 * ================================================================ */
static const char *g_ss_default_sni_pool[] = {
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "ajax.googleapis.com",
    "fonts.googleapis.com",
    "unpkg.com",
    "cdn.bootcdn.net",
    "lib.baomitu.com",
    "assets-cdn.github.com",
    "stackpath.bootstrapcdn.com",
    "use.fontawesome.com",
};
#define SS_DEFAULT_SNI_POOL_SIZE \
    (sizeof(g_ss_default_sni_pool) / sizeof(g_ss_default_sni_pool[0]))

/* Discovered local CDN SNI pool (set by moor_shitstorm_discover_local_snis) */
#define SS_MAX_DISCOVERED_SNI  64
static char g_ss_discovered_sni_buf[SS_MAX_DISCOVERED_SNI][256];
static const char *g_ss_discovered_sni[SS_MAX_DISCOVERED_SNI];
static int g_ss_discovered_sni_count = 0;

static int ss_sni_pool_size(void) {
    return g_ss_discovered_sni_count > 0
        ? g_ss_discovered_sni_count
        : (int)SS_DEFAULT_SNI_POOL_SIZE;
}

static const char *ss_sni_pool_get(int idx) {
    if (g_ss_discovered_sni_count > 0)
        return g_ss_discovered_sni[idx % g_ss_discovered_sni_count];
    return g_ss_default_sni_pool[idx % SS_DEFAULT_SNI_POOL_SIZE];
}

static void ss_random_sni(char *out, size_t out_len) {
    uint32_t idx;
    moor_crypto_random((uint8_t *)&idx, sizeof(idx));
    snprintf(out, out_len, "%s", ss_sni_pool_get((int)(idx % (uint32_t)ss_sni_pool_size())));
}

/* ================================================================
 * CDN seed list (used as starting probes for dynamic discovery)
 *
 * These are NOT used directly as SNIs.  They seed the forward-DNS
 * phase: resolve each, GeoIP-check the resolved IP, and optionally
 * reverse-DNS the IP to capture local edge hostnames.
 * ================================================================ */
static const char *g_cdn_seed_list[] = {
    /* Global CDNs with wide edge coverage */
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "ajax.googleapis.com",
    "fonts.googleapis.com",
    "unpkg.com",
    "cdn.bootcdn.net",
    "lib.baomitu.com",
    "assets-cdn.github.com",
    "stackpath.bootstrapcdn.com",
    "use.fontawesome.com",
    /* Cloud providers (global edge) */
    "d1.awsstatic.com",
    "az764295.vo.msecnd.net",
    "akamai.net",
    "fastly.net",
    /* Regional CDNs */
    "cdn.staticfile.org",
    "cdn.bootcss.com",
    "lf1-cdn-tos.bytegoofy.com",
    "static.cloudflareinsights.com",
    "cdn.shopify.com",
    "images-na.ssl-images-amazon.com",
    "ssl.gstatic.com",
    "www.gstatic.com",
    "fonts.gstatic.com",
    "apis.google.com",
    "maps.googleapis.com",
    "translate.googleapis.com",
    "play.googleapis.com",
    "lh3.googleusercontent.com",
    "i.ytimg.com",
    "yt3.ggpht.com",
    "static.xx.fbcdn.net",
    "scontent.xx.fbcdn.net",
    "abs.twimg.com",
    "pbs.twimg.com",
    "cdn.discordapp.com",
    "media.discordapp.net",
    "i.imgur.com",
    "i.redd.it",
    "preview.redd.it",
    "cdn.akamai.steamstatic.com",
    "store-images.s-microsoft.com",
    "img-prod-cms-rt-microsoft-com.akamaized.net",
    "cdn.ampproject.org",
    "pagead2.googlesyndication.com",
    "connect.facebook.net",
    "platform.twitter.com",
    "js.stripe.com",
    "cdn.segment.com",
    "widget.intercom.io",
};
#define CDN_SEED_LIST_SIZE \
    (sizeof(g_cdn_seed_list) / sizeof(g_cdn_seed_list[0]))

/* ================================================================
 * SNI hostname discovery helpers
 * ================================================================ */

/* CDN subdomain prefixes for country-TLD heuristic probing */
static const char *cdn_prefixes[] = {
    "cdn", "static", "media", "assets", "images", "content",
    "cache", "dl", "download", "files", "storage", "cloud",
};
#define CDN_PREFIX_COUNT \
    (sizeof(cdn_prefixes) / sizeof(cdn_prefixes[0]))

/* ================================================================
 * Per-country CDN intelligence table
 *
 * Hardcoded CDN domains known to have infrastructure (PoPs) in
 * each country.  Sourced from cdnplanet.com coverage data and
 * seramo/cdn-ip-ranges (Cloudflare, Fastly, Gcore ranges).
 *
 * This table is consulted first (Method 0) because it is instant
 * (no network queries) and seeds the SNI pool with highly
 * plausible local CDN domains before any dynamic probing.
 * ================================================================ */
typedef struct {
    const char *cc;           /* ISO 3166-1 alpha-2 */
    const char *domains[16];  /* CDN domains with local infrastructure, NULL-terminated */
} country_cdn_t;

static const country_cdn_t g_country_cdns[] = {
    {"IR", {"arvancloud.ir", "cdn.arvancloud.com", "arvan.cloud",
            "cdn.cdnw.net", "cdn.cdnvideo.com", NULL}},
    {"CN", {"cdn.bootcdn.net", "lib.baomitu.com", "cdn.ccgslb.com",
            "cdn.dnsv1.com", "bytecdn.cn", "byteimg.com",
            "en.ksyun.com", "ks-cdn.com", "edgenext.com", NULL}},
    {"RU", {"cdnvideo.ru", "cdn.cdnvideo.ru", "mncdn.com",
            "cdn.cdnw.net", "edgenext.com", NULL}},
    {"TR", {"mncdn.com", "mncdn.net", "medianova.com",
            "cdn.cdnw.net", NULL}},
    {"IN", {"stackpathcdn.com", "cdn.cdnw.net", "cdn.b-cdn.net",
            "gcdn.co", NULL}},
    {"BR", {"cdn.cdnw.net", "cdn.gcdn.co", "cdn.b-cdn.net",
            "centurylink.net", NULL}},
    {"EG", {"cdn.cdnw.net", "cdn.gcdn.co", "mncdn.com", NULL}},
    {"SA", {"mncdn.com", "cdn.cdnw.net", "cdn.gcdn.co", NULL}},
    {"ID", {"cdn.ccgslb.com", "cdn.cdnw.net", "ks-cdn.com", NULL}},
    {"PK", {"mncdn.com", "cdn.cdnw.net", "cdn.gcdn.co", NULL}},
    {"VN", {"bytecdn.cn", "cdn.dnsv1.com", "cdn.cdnw.net", NULL}},
    {"TH", {"ks-cdn.com", "cdn.cdnw.net", "bytecdn.cn", NULL}},
    {"AE", {"mncdn.com", "ks-cdn.com", "cdn.cdnw.net", "cdn.gcdn.co", NULL}},
    {"VE", {"centurylink.net", NULL}},
    {"MM", {"cdn.cdnw.net", "edgenext.com", "bytecdn.cn", NULL}},
    {"CU", {NULL}},  /* no CDN PoPs */
    {NULL, {NULL}}
};

/* Global CDN edge domains -- high collateral damage if blocked.
 * Added as fallback after country-specific domains. */
static const char *g_global_cdn_edges[] = {
    "cdnjs.cloudflare.com",
    "ajax.googleapis.com",
    "fonts.googleapis.com",
    "ssl.gstatic.com",
    "global.ssl.fastly.net",
    "cdn.b-cdn.net",
    "cdn.rsc.cdn77.org",
    "cachefly.net",
    NULL
};

/* ================================================================
 * Local CDN discovery implementation -- dynamic multi-method
 *
 * Discovery methods (tried in order, results combined):
 *
 *   Method 0: Per-country CDN intelligence (instant, no network).
 *             Hardcoded table of CDN domains known to have PoPs
 *             in each country.  Seeds the pool immediately.
 *
 *   Method 0.5: Shodan API queries (if ~/.moor/shodan.key exists).
 *               Three queries: reverse DNS on client's /24, CDN
 *               hosts in client's ASN, and hostnames/certs for the
 *               client's own IP.  More comprehensive than local PTR
 *               queries but requires a Shodan API key.
 *
 *   Method 1: Reverse DNS scan of client's /24 neighborhood.
 *             Sample ~50 IPs across current and adjacent /24s,
 *             PTR-lookup each, filter for CDN-like hostnames.
 *
 *   Method 2: Forward-resolve seed CDN domains + GeoIP check.
 *             Resolve known CDN domains, keep those whose edge
 *             server IP is in the client's country.  Reverse-DNS
 *             the matched IPs to capture local edge hostnames.
 *
 *   Method 3: Country-TLD heuristic scan.
 *             For the client's country TLD, try common CDN
 *             subdomains (cdn.<tld>, static.<tld>, etc.) and
 *             keep anything that resolves.
 *
 *   Fallback: Global CDN edges (high collateral damage domains).
 *
 * Results are deduplicated and cached per-country for 24 hours.
 * Falls back to seed list if dynamic discovery finds nothing.
 * ================================================================ */

/* Country lookup via ip-api.com (same pattern as relay.c)
 * WARNING: plaintext HTTP -- geolocation query visible to local ISP.
 * Only called from bridge side (is_bridge=1) where this is acceptable. */
static uint16_t ss_lookup_country_ipapi(const char *ip) {
    int fd = moor_tcp_connect_simple("ip-api.com", 80);
    if (fd < 0) return 0;
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char req[256];
    int rlen = snprintf(req, sizeof(req),
        "GET /line/%s?fields=countryCode HTTP/1.0\r\n"
        "Host: ip-api.com\r\n\r\n", ip);
    if (rlen < 0 || (size_t)rlen >= sizeof(req)) { close(fd); return 0; }
    if (send(fd, req, rlen, MSG_NOSIGNAL) != rlen) { close(fd); return 0; }

    char buf[512];
    size_t total = 0;
    for (;;) {
        ssize_t n = recv(fd, buf + total, sizeof(buf) - 1 - total, 0);
        if (n <= 0) break;
        total += (size_t)n;
        if (total >= sizeof(buf) - 1) break;
    }
    close(fd);
    buf[total] = '\0';

    char *body = strstr(buf, "\r\n\r\n");
    if (!body) return 0;
    body += 4;
    while (*body == ' ' || *body == '\n' || *body == '\r') body++;
    if (strlen(body) < 2) return 0;
    char cc[3] = { body[0], body[1], '\0' };
    if (cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z') return 0;
    return moor_geoip_pack_country(cc);
}

/* Auto-detect our public IP, country, and ASN via ip-api.com.
 * WARNING: plaintext HTTP -- query and response visible to local ISP.
 * Only called from bridge side where this is acceptable.
 * When called with no specific IP, ip-api.com returns the caller's own info.
 * Returns packed country code; writes detected IP to ip_out, ASN string to
 * asn_out if non-NULL. */
static uint16_t ss_detect_own_ip_and_country(char *ip_out, size_t ip_len,
                                             char *asn_out, size_t asn_len) {
    int fd = moor_tcp_connect_simple("ip-api.com", 80);
    if (fd < 0) return 0;
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Request country code, IP, and AS number */
    const char *req =
        "GET /line/?fields=countryCode,query,as HTTP/1.0\r\n"
        "Host: ip-api.com\r\n\r\n";
    size_t rlen = strlen(req);
    if (send(fd, req, rlen, MSG_NOSIGNAL) != (ssize_t)rlen) { close(fd); return 0; }

    char buf[512];
    size_t total = 0;
    for (;;) {
        ssize_t n = recv(fd, buf + total, sizeof(buf) - 1 - total, 0);
        if (n <= 0) break;
        total += (size_t)n;
        if (total >= sizeof(buf) - 1) break;
    }
    close(fd);
    buf[total] = '\0';

    char *body = strstr(buf, "\r\n\r\n");
    if (!body) return 0;
    body += 4;
    while (*body == ' ' || *body == '\n' || *body == '\r') body++;

    /* ip-api /line/ returns fields one per line: countryCode\nquery\nas\n */
    char *line1 = body;
    char *nl = strchr(line1, '\n');
    if (!nl || (nl - line1) < 2) return 0;

    /* Parse country code from first line */
    char cc[3];
    cc[0] = line1[0]; cc[1] = line1[1]; cc[2] = '\0';
    if (cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z') return 0;

    /* Parse IP from second line */
    char *line2 = nl + 1;
    while (*line2 == '\r' || *line2 == ' ') line2++;
    if (ip_out && ip_len > 0) {
        size_t iplen = 0;
        while (line2[iplen] && line2[iplen] != '\n' && line2[iplen] != '\r'
               && iplen < ip_len - 1)
            iplen++;
        memcpy(ip_out, line2, iplen);
        ip_out[iplen] = '\0';
    }

    /* Parse ASN from third line (e.g. "AS44244 Irancell") */
    char *nl2 = strchr(line2, '\n');
    if (nl2 && asn_out && asn_len > 0) {
        char *line3 = nl2 + 1;
        while (*line3 == '\r' || *line3 == ' ') line3++;
        size_t alen = 0;
        while (line3[alen] && line3[alen] != '\n' && line3[alen] != '\r'
               && alen < asn_len - 1)
            alen++;
        memcpy(asn_out, line3, alen);
        asn_out[alen] = '\0';
    }

    return moor_geoip_pack_country(cc);
}

/* Load cached SNI list from file.  Returns number loaded (0 = no cache). */
static int ss_load_sni_cache(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;

    /* First line: timestamp (unix seconds).  Expire after 24 hours. */
    char line[512];
    if (!fgets(line, sizeof(line), fp)) { fclose(fp); return 0; }
    long ts = atol(line);
    if ((long)time(NULL) - ts > 86400) { fclose(fp); return 0; } /* stale */

    int count = 0;
    while (fgets(line, sizeof(line), fp) && count < SS_MAX_DISCOVERED_SNI) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        if (len == 0) continue;
        snprintf(g_ss_discovered_sni_buf[count], 256, "%s", line);
        g_ss_discovered_sni[count] = g_ss_discovered_sni_buf[count];
        count++;
    }
    fclose(fp);
    return count;
}

/* Save discovered SNI list to cache file */
static void ss_save_sni_cache(const char *path, int count) {
    if (!path || !path[0]) return;
    FILE *fp = fopen(path, "w");
    if (!fp) return;
    fprintf(fp, "%ld\n", (long)time(NULL));
    for (int i = 0; i < count; i++)
        fprintf(fp, "%s\n", g_ss_discovered_sni[i]);
    fclose(fp);
}

/* Check if hostname matches CDN-like patterns (case-insensitive substring) */
/* Reject ISP PTR records that encode IP addresses (e.g.
 * "50-33-69-1.static.mskg.mi.ip.frontiernet.net").
 * These look nothing like CDN domains and are a DPI red flag.
 * Pattern: first label starts with digits separated by dashes. */
static int ss_is_isp_ptr_record(const char *host) {
    /* Check if first label matches N-N-N-N pattern (IP encoded with dashes) */
    const char *dot = strchr(host, '.');
    if (!dot) return 0;
    size_t first_label_len = (size_t)(dot - host);
    if (first_label_len < 7) return 0; /* "1-2-3-4" minimum */
    int dashes = 0, digits = 0;
    for (size_t i = 0; i < first_label_len; i++) {
        if (host[i] == '-') dashes++;
        else if (host[i] >= '0' && host[i] <= '9') digits++;
    }
    /* If first label is mostly digits and dashes (like "50-33-69-1"), it's ISP PTR */
    if (dashes >= 2 && digits >= 4 &&
        (size_t)(dashes + digits) > first_label_len * 2 / 3)
        return 1;

    /* Also reject known ISP reverse-DNS patterns */
    if (strstr(host, ".ip.") || strstr(host, ".static.") ||
        strstr(host, ".dsl.") || strstr(host, ".cable.") ||
        strstr(host, ".dhcp.") || strstr(host, ".pool.") ||
        strstr(host, ".dial.") || strstr(host, ".dynamic.") ||
        strstr(host, ".broadband.") || strstr(host, ".adsl.") ||
        strstr(host, ".cpe.") || strstr(host, ".customer.") ||
        strstr(host, ".res.") || strstr(host, ".residential."))
        return 1;

    return 0;
}

static int ss_is_good_sni_hostname(const char *host) {
    /* SNI must look like a plausible CDN or web service domain.
     * ISP PTR records (50-33-69-1.static.frontiernet.net) are NOT
     * plausible — no one does TLS to residential ISP hostnames. */
    size_t len = strlen(host);
    if (len < 4 || len > 253) return 0;

    if (!strchr(host, '.')) return 0;

    /* Reject bare IP addresses */
    struct in_addr dummy;
    if (inet_pton(AF_INET, host, &dummy) == 1) return 0;

    if (strstr(host, "localhost") || strstr(host, "localdomain")) return 0;

    int dot_count = 0;
    for (const char *p = host; *p; p++)
        if (*p == '.') dot_count++;
    if (dot_count < 1) return 0;

    /* Reject ISP PTR records — the big filter */
    if (ss_is_isp_ptr_record(host)) return 0;

    return 1;
}

/* Deduplicate: return 1 if hostname already in discovered list */
static int ss_sni_already_found(const char *host, int count) {
    for (int i = 0; i < count; i++) {
        if (strcmp(g_ss_discovered_sni[i], host) == 0)
            return 1;
    }
    return 0;
}

/* Add a hostname to the discovered SNI list.  Returns new count. */
static int ss_sni_add(const char *host, int count) {
    if (count >= SS_MAX_DISCOVERED_SNI) return count;
    if (ss_sni_already_found(host, count)) return count;
    /* Reject empty, too-short, or IP-literal hostnames */
    size_t hlen = strlen(host);
    if (hlen < 4) return count;
    /* Must contain at least one dot */
    if (!strchr(host, '.')) return count;
    snprintf(g_ss_discovered_sni_buf[count], 256, "%s", host);
    g_ss_discovered_sni[count] = g_ss_discovered_sni_buf[count];
    return count + 1;
}

/* ----------------------------------------------------------------
 * Method 0.5: Shodan API CDN discovery
 *
 * Uses the Shodan API (if a key is available at ~/.moor/shodan.key)
 * to discover CDN hostnames via three queries:
 *   Q1: Reverse DNS on client's /24 (samples ~20 IPs)
 *   Q2: Search for port:443 hosts in client's ASN
 *   Q3: Hostnames/certs for the client's own IP
 *
 * Falls through silently if no API key or on any error.
 * ---------------------------------------------------------------- */
/* Shodan API queries removed — no plaintext HTTP, no shell-out.
 * CDN discovery uses only: rDNS, GeoIP, country tables, TLD heuristics.
 * These require zero HTTP and leak no API keys or behavioral fingerprints.
 * If Shodan data is needed, the bridge operator can pre-populate
 * the SNI cache file ({data_dir}/sni_cache.txt) manually. */

/* ================================================================
 * Shodan API code was here — removed because:
 *   1. api.shodan.io over plaintext HTTP leaks the API key
 *   2. No TLS library available for HTTPS without shell-out
 *   3. The other 5 discovery methods (rDNS, GeoIP, country tables,
 *      TLD heuristics, forward resolve) work without any HTTP
 *   4. Bridge operators can pre-populate sni_cache.txt manually
 *      with Shodan data if desired
 * ================================================================ */

/* Placeholder — kept so the caller compiles without changes.
 * Always returns 0 (no additional domains found). */
static int ss_shodan_discover(const char *client_ip, const char *client_asn,
                              const char *data_dir, int found) {
    (void)client_ip; (void)client_asn; (void)data_dir;
    return found;
}

/* ----------------------------------------------------------------
 * Method 1: Reverse DNS scan of client's /24 neighborhood
 *
 * Sample ~50 IPs across the client's /24 and neighboring /24s.
 * PTR lookup reveals hostnames like cdn-123.ir, cache-edge-01.example.com.
 * Filter for CDN-like patterns in the hostname.
 * ---------------------------------------------------------------- */
static int ss_rdns_scan(const char *client_ip, int found, uint64_t deadline_ms) {
    struct in_addr base;
    if (inet_pton(AF_INET, client_ip, &base) != 1) return found;

    uint32_t ip = ntohl(base.s_addr);
    uint32_t base24 = ip & 0xFFFFFF00u;

    /* Sample IPs within each /24 */
    static const uint8_t samples[] = {1, 2, 5, 10, 20, 50, 100, 150, 200, 250};
    /* Current /24 plus two neighbors in each direction */
    static const int offsets[] = {0, -256, 256, -512, 512};
    int n_offsets = 5;
    int n_samples = 10;

    for (int o = 0; o < n_offsets && found < SS_MAX_DISCOVERED_SNI; o++) {
        for (int s = 0; s < n_samples && found < SS_MAX_DISCOVERED_SNI; s++) {
            /* Enforce deadline */
            if (moor_time_ms() > deadline_ms) {
                LOG_DEBUG("sni-discover: rdns scan hit deadline after %d found", found);
                return found;
            }

            int64_t probe_base = (int64_t)base24 + offsets[o];
            if (probe_base < 0 || probe_base > 0xFFFFFF00LL) continue;
            uint32_t probe_ip = htonl((uint32_t)probe_base + samples[s]);

            struct sockaddr_in sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET;
            sa.sin_addr.s_addr = probe_ip;

            /* R10-ADV1: Random delay between PTR queries to avoid burst
             * fingerprinting. Spreads ~50 queries over 5-25s instead of <1s. */
            usleep(100000 + randombytes_uniform(400000)); /* 100-500ms */

            char host[256];
            /* NI_NAMEREQD: fail if no PTR record (don't return numeric) */
            if (getnameinfo((struct sockaddr *)&sa, sizeof(sa),
                            host, sizeof(host), NULL, 0, NI_NAMEREQD) != 0)
                continue;

            /* Check if hostname looks CDN-like */
            if (ss_is_good_sni_hostname(host)) {
                int prev = found;
                found = ss_sni_add(host, found);
                if (found > prev)
                    LOG_DEBUG("sni-discover: rdns found CDN hostname: %s", host);
            }
        }
    }
    return found;
}

/* ----------------------------------------------------------------
 * Method 2: Forward-resolve seed CDN domains + GeoIP check +
 *           reverse DNS capture of local edge hostnames
 *
 * For each seed domain:
 *   1. DNS resolve to IP
 *   2. GeoIP-check: is the IP in the client's country?
 *   3. If yes: keep the original domain as SNI
 *   4. Also reverse-DNS the IP to capture the local edge hostname
 *      (e.g., fonts.googleapis.com -> PTR: iad-edge-01.google.com)
 * ---------------------------------------------------------------- */
static int ss_forward_resolve_scan(uint16_t our_cc,
                                   const moor_geoip_db_t *geoip_db,
                                   int found, int *ipapi_budget,
                                   uint64_t deadline_ms) {
    for (size_t i = 0; i < CDN_SEED_LIST_SIZE && found < SS_MAX_DISCOVERED_SNI; i++) {
        if (moor_time_ms() > deadline_ms) {
            LOG_DEBUG("sni-discover: forward scan hit deadline at seed %d, %d found",
                      (int)i, found);
            break;
        }

        const char *domain = g_cdn_seed_list[i];

        /* Skip if already discovered */
        if (ss_sni_already_found(domain, found)) continue;

        /* DNS resolve */
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(domain, NULL, &hints, &res) != 0 || !res) continue;

        int matched = 0;
        struct in_addr matched_addr;
        memset(&matched_addr, 0, sizeof(matched_addr));

        for (struct addrinfo *rp = res; rp && !matched; rp = rp->ai_next) {
            if (rp->ai_family != AF_INET) continue;
            struct sockaddr_in *sa = (struct sockaddr_in *)rp->ai_addr;
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sa->sin_addr, ip_str, sizeof(ip_str));

            uint16_t cdn_cc = 0;

            /* Try GeoIP DB first (fast, no network) */
            if (geoip_db && geoip_db->num_entries > 0) {
                const moor_geoip_entry_t *ent = moor_geoip_lookup(geoip_db, ip_str);
                if (ent) cdn_cc = ent->country_code;
            }

            /* Fall back to ip-api.com if no GeoIP DB, budget permitting
             * (ip-api.com allows 45 req/min) */
            if (!cdn_cc && (!geoip_db || geoip_db->num_entries == 0)
                && *ipapi_budget > 0) {
                cdn_cc = ss_lookup_country_ipapi(ip_str);
                (*ipapi_budget)--;
            }

            if (cdn_cc == our_cc) {
                matched = 1;
                matched_addr = sa->sin_addr;
            }
        }
        freeaddrinfo(res);

        if (!matched) continue;

        /* Add the original seed domain as SNI */
        found = ss_sni_add(domain, found);
        LOG_DEBUG("sni-discover: seed %s has local edge", domain);

        /* Bonus: reverse-DNS the matched IP to capture local edge hostname
         * (e.g., fonts.googleapis.com -> iad-edge-01.google.com) */
        struct sockaddr_in rev_sa;
        memset(&rev_sa, 0, sizeof(rev_sa));
        rev_sa.sin_family = AF_INET;
        rev_sa.sin_addr = matched_addr;
        char rev_host[256];
        if (getnameinfo((struct sockaddr *)&rev_sa, sizeof(rev_sa),
                        rev_host, sizeof(rev_host), NULL, 0, NI_NAMEREQD) == 0) {
            if (ss_is_good_sni_hostname(rev_host)) {
                int prev = found;
                found = ss_sni_add(rev_host, found);
                if (found > prev)
                    LOG_DEBUG("sni-discover: reverse DNS bonus: %s -> %s",
                              domain, rev_host);
            }
        }
    }
    return found;
}

/* ----------------------------------------------------------------
 * Method 3: Country-TLD heuristic scan
 *
 * Map the client's country code to the country's TLD, then try
 * resolving common CDN subdomains under that TLD.
 * ---------------------------------------------------------------- */

/* Map of country code -> ccTLD (covers censorship-heavy countries first,
 * then common ones).  Not exhaustive -- just the ones most likely to
 * have local CDN infrastructure worth mimicking. */
typedef struct { const char *cc; const char *tld; } cc_tld_entry_t;
static const cc_tld_entry_t cc_tld_map[] = {
    {"IR", "ir"}, {"CN", "cn"}, {"RU", "ru"}, {"TR", "tr"},
    {"EG", "eg"}, {"SA", "sa"}, {"AE", "ae"}, {"PK", "pk"},
    {"IN", "in"}, {"ID", "id"}, {"VN", "vn"}, {"TH", "th"},
    {"KZ", "kz"}, {"UZ", "uz"}, {"BY", "by"}, {"VE", "ve"},
    {"CU", "cu"}, {"MM", "mm"}, {"ET", "et"}, {"BD", "bd"},
    {"BR", "br"}, {"MX", "mx"}, {"KR", "kr"}, {"JP", "jp"},
    {"DE", "de"}, {"FR", "fr"}, {"GB", "uk"}, {"IT", "it"},
    {"ES", "es"}, {"PL", "pl"}, {"UA", "ua"}, {"NG", "ng"},
    {"ZA", "za"}, {"KE", "ke"}, {"AR", "ar"}, {"CO", "co"},
    {"CL", "cl"}, {"PE", "pe"}, {"MY", "my"}, {"PH", "ph"},
    {"TW", "tw"}, {"HK", "hk"}, {"SG", "sg"}, {"IL", "il"},
};
#define CC_TLD_MAP_SIZE (sizeof(cc_tld_map) / sizeof(cc_tld_map[0]))

/* Some popular local domain bases per country (Alexa-style top sites).
 * Try cdn.<base>, static.<base>, etc. */
typedef struct { const char *cc; const char *domains[8]; } cc_domains_entry_t;
static const cc_domains_entry_t cc_popular_domains[] = {
    {"IR", {"digikala.ir", "aparat.com", "snapp.ir", "filimo.com",
            "shaparak.ir", "namnak.com", "telewebion.com", NULL}},
    {"CN", {"taobao.com", "jd.com", "bilibili.com", "douyin.com",
            "zhihu.com", "weibo.com", "baidu.com", NULL}},
    {"RU", {"yandex.ru", "vk.com", "mail.ru", "ozon.ru",
            "wildberries.ru", "avito.ru", "sber.ru", NULL}},
    {"TR", {"hepsiburada.com", "trendyol.com", "sahibinden.com",
            "hurriyet.com.tr", "ensonhaber.com", NULL, NULL, NULL}},
    {"EG", {"jumia.com.eg", "souq.com", "masrawy.com", "filgoal.com",
            NULL, NULL, NULL, NULL}},
    {"IN", {"flipkart.com", "jiocinema.com", "hotstar.com", "myntra.com",
            "zomato.com", "swiggy.com", NULL, NULL}},
    {"BR", {"mercadolivre.com.br", "globo.com", "uol.com.br",
            "americanas.com.br", NULL, NULL, NULL, NULL}},
};
#define CC_POPULAR_DOMAINS_SIZE \
    (sizeof(cc_popular_domains) / sizeof(cc_popular_domains[0]))

static int ss_country_tld_scan(const char *our_cc_str, int found,
                               uint64_t deadline_ms) {
    /* Find the ccTLD for this country */
    const char *tld = NULL;
    for (size_t i = 0; i < CC_TLD_MAP_SIZE; i++) {
        if (our_cc_str[0] == cc_tld_map[i].cc[0] &&
            our_cc_str[1] == cc_tld_map[i].cc[1]) {
            tld = cc_tld_map[i].tld;
            break;
        }
    }

    /* Phase A: Try cdn.<popular_domain> for this country */
    for (size_t d = 0; d < CC_POPULAR_DOMAINS_SIZE; d++) {
        if (our_cc_str[0] != cc_popular_domains[d].cc[0] ||
            our_cc_str[1] != cc_popular_domains[d].cc[1])
            continue;
        for (int b = 0; b < 8 && cc_popular_domains[d].domains[b]; b++) {
            if (moor_time_ms() > deadline_ms || found >= SS_MAX_DISCOVERED_SNI)
                return found;
            for (size_t p = 0; p < CDN_PREFIX_COUNT && found < SS_MAX_DISCOVERED_SNI; p++) {
                if (moor_time_ms() > deadline_ms) return found;

                char probe[256];
                snprintf(probe, sizeof(probe), "%s.%s",
                         cdn_prefixes[p], cc_popular_domains[d].domains[b]);

                if (ss_sni_already_found(probe, found)) continue;

                struct addrinfo hints, *res = NULL;
                memset(&hints, 0, sizeof(hints));
                hints.ai_family = AF_INET;
                hints.ai_socktype = SOCK_STREAM;
                if (getaddrinfo(probe, NULL, &hints, &res) == 0 && res) {
                    freeaddrinfo(res);
                    int prev = found;
                    found = ss_sni_add(probe, found);
                    if (found > prev)
                        LOG_DEBUG("sni-discover: country-tld found: %s", probe);
                }
            }
        }
        break; /* Only process the matching country entry */
    }

    /* Phase B: Try generic cdn.<tld>, static.<tld> etc. */
    if (tld) {
        for (size_t p = 0; p < CDN_PREFIX_COUNT && found < SS_MAX_DISCOVERED_SNI; p++) {
            if (moor_time_ms() > deadline_ms) return found;

            char probe[256];
            snprintf(probe, sizeof(probe), "%s.%s", cdn_prefixes[p], tld);

            if (ss_sni_already_found(probe, found)) continue;

            struct addrinfo hints, *res = NULL;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(probe, NULL, &hints, &res) == 0 && res) {
                freeaddrinfo(res);
                int prev = found;
                found = ss_sni_add(probe, found);
                if (found > prev)
                    LOG_DEBUG("sni-discover: tld probe found: %s", probe);
            }
        }
    }

    return found;
}

/* ================================================================
 * Push discovered SNIs to both ShitStorm and Mirage transports
 * ================================================================ */
static void ss_push_sni_pool(int count) {
    g_ss_discovered_sni_count = count;

    /* Build CSV and push to Mirage transport */
    char csv[8192] = {0};
    size_t off = 0;
    for (int i = 0; i < count && off < sizeof(csv) - 260; i++) {
        if (i > 0) csv[off++] = ',';
        off += (size_t)snprintf(csv + off, sizeof(csv) - off, "%s",
                                g_ss_discovered_sni[i]);
    }
    extern void moor_mirage_set_sni_pool(const char *csv);
    moor_mirage_set_sni_pool(csv);
}

/* ================================================================
 * Main entry point: dynamic multi-method CDN discovery
 * ================================================================ */
void moor_shitstorm_discover_local_snis(const char *our_public_ip,
                                        const moor_geoip_db_t *geoip_db,
                                        const char *data_dir,
                                        int is_bridge) {
    /* Auto-detect public IP if caller passed NULL.
     * On bridge side: uses ip-api.com (plaintext HTTP, acceptable).
     * On client side: requires GeoIP DB -- never makes plaintext HTTP
     * queries that would be visible to the censoring ISP. */
    char detected_ip[64] = {0};
    char detected_asn[128] = {0};
    uint16_t detected_cc = 0;
    if (!our_public_ip || !our_public_ip[0]) {
        if (!is_bridge) {
            /* Client side: refuse to auto-detect via plaintext HTTP.
             * The client's ISP would see an HTTP query to ip-api.com,
             * which is a censorship-evasion fingerprint. */
            LOG_WARN("sni-discover: client mode without IP, skipping "
                     "plaintext HTTP auto-detect (leak risk)");
            if (geoip_db && geoip_db->num_entries > 0) {
                LOG_INFO("sni-discover: client will use GeoIP DB + "
                         "local methods only");
            } else {
                LOG_WARN("sni-discover: no GeoIP DB and no IP, "
                         "using default SNI pool");
                return;
            }
        } else {
            LOG_INFO("sni-discover: no IP provided, auto-detecting via ip-api.com");
            detected_cc = ss_detect_own_ip_and_country(
                detected_ip, sizeof(detected_ip),
                detected_asn, sizeof(detected_asn));
            if (!detected_cc || !detected_ip[0]) {
                LOG_WARN("sni-discover: auto-detect failed, using default SNI pool");
                return;
            }
            our_public_ip = detected_ip;
            LOG_INFO("sni-discover: detected IP %s, ASN: %s", detected_ip,
                     detected_asn[0] ? detected_asn : "(unknown)");
        }
    }

    /* Fast path: check disk cache first (valid for 24 hours) */
    char cache_path[512] = {0};
    if (data_dir && data_dir[0]) {
        snprintf(cache_path, sizeof(cache_path), "%s/sni_cache.txt", data_dir);
        int cached = ss_load_sni_cache(cache_path);
        if (cached > 0) {
            LOG_INFO("sni-discover: loaded %d cached local CDN domains", cached);
            ss_push_sni_pool(cached);
            return;
        }
    }

    /* Determine our country code */
    uint16_t our_cc = detected_cc;

    /* Try GeoIP database first (no network round-trip) */
    if (!our_cc && geoip_db && geoip_db->num_entries > 0) {
        const moor_geoip_entry_t *ent = moor_geoip_lookup(geoip_db, our_public_ip);
        if (ent) our_cc = ent->country_code;
    }

    /* Fall back to ip-api.com (bridge only -- plaintext HTTP) */
    if (!our_cc && is_bridge && our_public_ip) {
        our_cc = ss_lookup_country_ipapi(our_public_ip);
    }

    if (!our_cc) {
        if (!our_public_ip) {
            LOG_WARN("sni-discover: no country and no IP, using default SNI pool");
            return;
        }
        LOG_INFO("sni-discover: no GeoIP for %s, resolving CDN seed domains directly",
                 our_public_ip);
        /* No country = can't do GeoIP filtering.  Instead of rDNS (which
         * produces ISP PTR garbage like "50-33-69-1.static.frontiernet.net"),
         * resolve the global CDN seed list.  These are real CDN domains that
         * look plausible as SNI regardless of country. */
        int found = 0;
        for (size_t i = 0; i < CDN_SEED_LIST_SIZE && found < SS_MAX_DISCOVERED_SNI; i++) {
            const char *domain = g_cdn_seed_list[i];
            struct addrinfo hints = {0}, *res = NULL;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(domain, NULL, &hints, &res) == 0 && res) {
                found = ss_sni_add(domain, found);
                LOG_DEBUG("sni-discover: CDN seed resolved: %s", domain);
                freeaddrinfo(res);
            }
        }
        /* Add global CDN edges as well */
        for (int i = 0; g_global_cdn_edges[i] && found < SS_MAX_DISCOVERED_SNI; i++) {
            found = ss_sni_add(g_global_cdn_edges[i], found);
        }
        if (found > 0) {
            LOG_INFO("sni-discover: resolved %d CDN domains (no GeoIP needed)", found);
            ss_push_sni_pool(found);
            ss_save_sni_cache(cache_path, found);
        } else {
            LOG_WARN("sni-discover: CDN resolution failed, using default SNI pool");
        }
        return;
    }

    char our_cc_str[3];
    moor_geoip_unpack_country(our_cc, our_cc_str);
    LOG_INFO("sni-discover: country %s, starting dynamic multi-method discovery",
             our_cc_str);

    uint64_t start_ms = moor_time_ms();
    uint64_t deadline_ms = start_ms + 10000; /* 10 second hard deadline */
    int found = 0;
    /* ip-api.com budget: disabled by default on both sides to prevent
     * plaintext HTTP probing leaks (#R1-A4).  Only enable with explicit
     * config flag (MOOR_IPAPI_ENABLE=1). */
    int ipapi_budget = 0;
    const char *ipapi_env = getenv("MOOR_IPAPI_ENABLE");
    if (is_bridge && ipapi_env && strcmp(ipapi_env, "1") == 0)
        ipapi_budget = 15;

    /* Method 0: Per-country CDN intelligence (instant, no network queries) */
    for (int i = 0; g_country_cdns[i].cc; i++) {
        if (strcmp(our_cc_str, g_country_cdns[i].cc) == 0) {
            int before_m0 = found;
            for (int j = 0; g_country_cdns[i].domains[j]; j++) {
                found = ss_sni_add(g_country_cdns[i].domains[j], found);
            }
            LOG_INFO("sni-discover: method 0 -- added %d known CDN domains for %s",
                     found - before_m0, our_cc_str);
            break;
        }
    }

    /* Method 0.5: Shodan API CDN discovery (bridge only -- plaintext HTTP
     * leaks the API key and discovery intent to the local ISP) */
    if (is_bridge && found < SS_MAX_DISCOVERED_SNI
        && moor_time_ms() < deadline_ms) {
        int before_shodan = found;
        found = ss_shodan_discover(our_public_ip, detected_asn, data_dir, found);
        if (found > before_shodan)
            LOG_INFO("sni-discover: shodan found %d CDN hostnames (%lums)",
                     found - before_shodan,
                     (unsigned long)(moor_time_ms() - start_ms));
    } else if (!is_bridge) {
        LOG_INFO("sni-discover: skipping Shodan on client (plaintext HTTP leak risk)");
    }

    /* Method 1: Reverse DNS scan of client's /24 neighborhood */
    LOG_INFO("sni-discover: method 1 -- reverse DNS scan of %s neighborhood",
             our_public_ip);
    int before_rdns = found;
    found = ss_rdns_scan(our_public_ip, found, deadline_ms);
    LOG_INFO("sni-discover: rdns scan found %d CDN hostnames (%lums)",
             found - before_rdns, (unsigned long)(moor_time_ms() - start_ms));

    /* Method 2: Forward resolve seed CDN domains + GeoIP + reverse DNS bonus */
    if (found < SS_MAX_DISCOVERED_SNI && moor_time_ms() < deadline_ms) {
        LOG_INFO("sni-discover: method 2 -- forward resolve %d seed domains",
                 (int)CDN_SEED_LIST_SIZE);
        int before_fwd = found;
        found = ss_forward_resolve_scan(our_cc, geoip_db, found,
                                        &ipapi_budget, deadline_ms);
        LOG_INFO("sni-discover: forward scan found %d additional domains (%lums)",
                 found - before_fwd, (unsigned long)(moor_time_ms() - start_ms));
    }

    /* Method 3: Country-TLD heuristic scan */
    if (found < SS_MAX_DISCOVERED_SNI && moor_time_ms() < deadline_ms) {
        LOG_INFO("sni-discover: method 3 -- country-TLD heuristic for %s",
                 our_cc_str);
        int before_tld = found;
        found = ss_country_tld_scan(our_cc_str, found, deadline_ms);
        LOG_INFO("sni-discover: tld scan found %d additional domains (%lums)",
                 found - before_tld, (unsigned long)(moor_time_ms() - start_ms));
    }

    /* Fallback: Global CDN edges (high collateral damage, work everywhere) */
    if (found < SS_MAX_DISCOVERED_SNI) {
        int before_global = found;
        for (int i = 0; g_global_cdn_edges[i]; i++) {
            found = ss_sni_add(g_global_cdn_edges[i], found);
            if (found >= SS_MAX_DISCOVERED_SNI) break;
        }
        if (found > before_global)
            LOG_INFO("sni-discover: fallback -- added %d global CDN edge domains",
                     found - before_global);
    }

    uint64_t elapsed = moor_time_ms() - start_ms;

    /* Apply results or fall back to seed list */
    if (found == 0) {
        LOG_INFO("sni-discover: no local CDN infrastructure found in %s (%lums), "
                 "using default SNI pool", our_cc_str, (unsigned long)elapsed);
        return;
    }

    LOG_INFO("sni-discover: discovered %d CDN domains for %s in %lums:",
             found, our_cc_str, (unsigned long)elapsed);
    for (int i = 0; i < found; i++)
        LOG_INFO("  sni-discover: [%d] %s", i + 1, g_ss_discovered_sni[i]);

    ss_push_sni_pool(found);

    /* Cache to disk for fast restarts */
    if (cache_path[0])
        ss_save_sni_cache(cache_path, found);
}

/* Key rotation interval: ratchet all keys every 2^16 records.
 * Defeats session anomaly detectors that flag connections with unusually
 * high nonce counters or long-lived symmetric keys. */
#define SS_REKEY_INTERVAL  65536

/* ================================================================
 * Transport state -- double encryption layers
 * ================================================================ */
typedef struct moor_transport_state {
    /* Outer layer keys (TLS 1.3 record encryption) */
    uint8_t  outer_send_key[32];
    uint8_t  outer_recv_key[32];
    uint64_t outer_send_nonce;
    uint64_t outer_recv_nonce;
    /* Inner layer keys (Scramble-style length obfuscation + inner AEAD) */
    uint8_t  inner_send_key[32];
    uint8_t  inner_recv_key[32];
    uint8_t  header_send_key[32];
    uint8_t  header_recv_key[32];
    uint64_t inner_send_nonce;
    uint64_t inner_recv_nonce;
    /* Buffered data from prior reads */
    uint8_t  recv_buf[8192];
    size_t   recv_len;
    uint64_t records_sent;
    /* Key rotation: explicit epoch counters for ratchet (#5).
     * Both sides track independently so any record counting mismatch
     * doesn't cause permanent key desync. */
    uint32_t rekey_epoch;        /* send-side epoch */
    uint32_t rekey_recv_epoch;   /* recv-side epoch */
    /* Receive-side record counter for symmetric key rotation */
    uint64_t records_received;
    /* HTTP/2 framing (#1): post-handshake content looks like h2 */
    int      h2_sent_preface;
    uint32_t h2_stream_id;      /* odd = client-initiated, even = server push */
} shitstorm_state_t;

/* ================================================================
 * Helpers
 * ================================================================ */

/* Forward declarations for handshake helpers used before definition */
static int ss_send_fake_new_session_tickets(int fd, shitstorm_state_t *st);
static int ss_recv_fake_new_session_tickets(int fd, shitstorm_state_t *st);

static int ss_send_all(int fd, const uint8_t *data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, (const char *)data + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int ss_recv_all(int fd, uint8_t *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
#ifndef _WIN32
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int pr = poll(&pfd, 1, 30000);
        if (pr <= 0) return -1;
#endif
        ssize_t n = recv(fd, (char *)buf + total, len - total, 0);
        if (n <= 0) return -1;
        total += (size_t)n;
    }
    return 0;
}

static void ss_tls_record_header(uint8_t *hdr, uint8_t type, uint16_t length) {
    hdr[0] = type;
    hdr[1] = 0x03;
    hdr[2] = 0x03; /* TLS 1.2 on wire */
    hdr[3] = (uint8_t)(length >> 8);
    hdr[4] = (uint8_t)(length);
}

/* XOR 2-byte length header with ChaCha20 keystream (from Scramble) */
static void ss_xor_header(uint8_t hdr[2], const uint8_t key[32], uint64_t nonce) {
    uint8_t nonce_buf[12];
    memset(nonce_buf, 0, sizeof(nonce_buf));
    for (int i = 0; i < 8; i++)
        nonce_buf[i] = (uint8_t)(nonce >> (i * 8));
    uint8_t keystream[2];
    memset(keystream, 0, 2);
    crypto_stream_chacha20_ietf_xor(keystream, keystream, 2, nonce_buf, key);
    hdr[0] ^= keystream[0];
    hdr[1] ^= keystream[1];
}

/* ================================================================
 * Fake encrypted handshake records (from Mirage)
 *
 * Sends exactly SS_FAKE_HS_RECORD_COUNT TLS Application Data records
 * with random content totalling 2000-4000 bytes, mimicking the
 * certificate chain in real TLS 1.3.
 *
 * Both sides use the same fixed count -- no end-marker needed.
 * (The previous zero-length Application Data marker violated
 * RFC 8446 section 5.1 which forbids zero-length app data records.)
 * ================================================================ */
#define SS_FAKE_HS_RECORD_COUNT 4

static int ss_send_fake_encrypted_hs(int fd) {
    /* #7 Cert chain realism: real TLS 1.3 servers send EncryptedExtensions +
     * Certificate + CertificateVerify + Finished in these records.
     * Let's Encrypt chain (RSA-2048 leaf + R3 intermediate + ISRG root) is
     * typically 3500-5500 bytes.  Previous range (2000-4000) was too small
     * for a 3-cert RSA chain, flagging us as anomalous. */
    uint32_t rval;
    moor_crypto_random((uint8_t *)&rval, sizeof(rval));
    size_t total_target = 3500 + (rval % 2001); /* 3500-5500 bytes */
    size_t remaining = total_target;

    for (int i = 0; i < SS_FAKE_HS_RECORD_COUNT; i++) {
        size_t rec_payload;
        if (i == SS_FAKE_HS_RECORD_COUNT - 1) {
            rec_payload = remaining;
        } else {
            uint32_t frac;
            moor_crypto_random((uint8_t *)&frac, sizeof(frac));
            int left = SS_FAKE_HS_RECORD_COUNT - i;
            size_t avg = remaining / (size_t)left;
            rec_payload = (avg * 60 + (avg * 80 * (frac % 100)) / 100) / 100;
            if (rec_payload > remaining) rec_payload = remaining;
            if (rec_payload < 32) rec_payload = 32;
        }
        if (rec_payload > TLS_MAX_FRAGMENT) rec_payload = TLS_MAX_FRAGMENT;

        uint8_t hdr[TLS_RECORD_HEADER];
        ss_tls_record_header(hdr, TLS_APPLICATION_DATA, (uint16_t)rec_payload);
        if (ss_send_all(fd, hdr, TLS_RECORD_HEADER) != 0) return -1;

        size_t sent = 0;
        while (sent < rec_payload) {
            uint8_t chunk[512];
            size_t csz = rec_payload - sent;
            if (csz > sizeof(chunk)) csz = sizeof(chunk);
            moor_crypto_random(chunk, csz);
            if (ss_send_all(fd, chunk, csz) != 0) return -1;
            sent += csz;
        }
        remaining -= rec_payload;
    }

    return 0;
}

/* Consume exactly SS_FAKE_HS_RECORD_COUNT fake encrypted HS records */
static int ss_recv_fake_encrypted_hs(int fd) {
    for (int i = 0; i < SS_FAKE_HS_RECORD_COUNT; i++) {
        uint8_t hdr[TLS_RECORD_HEADER];
        if (ss_recv_all(fd, hdr, TLS_RECORD_HEADER) != 0) return -1;
        if (hdr[0] != TLS_APPLICATION_DATA) return -1;
        uint16_t rec_len = ((uint16_t)hdr[3] << 8) | hdr[4];
        if (rec_len == 0 || rec_len > TLS_MAX_FRAGMENT) return -1;

        size_t consumed = 0;
        while (consumed < rec_len) {
            uint8_t discard[512];
            size_t csz = rec_len - consumed;
            if (csz > sizeof(discard)) csz = sizeof(discard);
            if (ss_recv_all(fd, discard, csz) != 0) return -1;
            consumed += csz;
        }
    }
    return 0;
}

/* ================================================================
 * ClientHello / ServerHello builders
 *
 * The ClientHello matches Chrome 110+ JA4 fingerprint:
 *   t13d1516h2_8daaf6152771_02713d6af862
 *
 * - 16 cipher suites (1 GREASE + 15 real, in Chrome's order)
 * - 16 extensions with proper data + 1-2 GREASE extensions
 * - Extension order randomized per connection (Fisher-Yates)
 * - GREASE values randomized per connection (0x?a?a pattern)
 * - Real x25519 key_share (Elligator2-representable)
 * - session_id = HMAC(node_id, client_random) for probe resistance
 * ================================================================ */

/* Generate a random GREASE value (0x0a0a, 0x1a1a, ..., 0xfafa) */
static uint16_t ss_random_grease(void) {
    uint8_t r;
    moor_crypto_random(&r, 1);
    uint8_t nibble = r % 16;
    uint8_t byte_val = (uint8_t)((nibble << 4) | 0x0a);
    return (uint16_t)((byte_val << 8) | byte_val);
}

/* Chrome's 15 cipher suites (GREASE is prepended separately) */
static const uint16_t chrome_ciphers[] = {
    0x1301, /* TLS_AES_128_GCM_SHA256 */
    0x1302, /* TLS_AES_256_GCM_SHA384 */
    0x1303, /* TLS_CHACHA20_POLY1305_SHA256 */
    0xc02b, /* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
    0xc02f, /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
    0xc02c, /* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */
    0xc030, /* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 */
    0xcca9, /* TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 */
    0xcca8, /* TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305 */
    0xc013, /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA */
    0xc014, /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA */
    0x009c, /* TLS_RSA_WITH_AES_128_GCM_SHA256 */
    0x009d, /* TLS_RSA_WITH_AES_256_GCM_SHA384 */
    0x002f, /* TLS_RSA_WITH_AES_128_CBC_SHA */
    0x0035, /* TLS_RSA_WITH_AES_256_CBC_SHA */
};
#define CHROME_CIPHER_COUNT  15

/* Chrome's 8 signature algorithms */
static const uint16_t chrome_sigalgs[] = {
    0x0403, /* ecdsa_secp256r1_sha256 */
    0x0804, /* rsa_pss_rsae_sha256 */
    0x0401, /* rsa_pkcs1_sha256 */
    0x0503, /* ecdsa_secp384r1_sha384 */
    0x0805, /* rsa_pss_rsae_sha384 */
    0x0501, /* rsa_pkcs1_sha384 */
    0x0806, /* rsa_pss_rsae_sha512 */
    0x0601, /* rsa_pkcs1_sha512 */
};
#define CHROME_SIGALG_COUNT  8

/* Extension TLV entry for shuffle-then-serialize */
#define SS_MAX_EXT_DATA  1280   /* X25519Kyber768 key_share needs ~1220 bytes */
#define SS_MAX_EXTENSIONS 24    /* Chrome 130: 16 real + up to 3 GREASE + ECH + PSK */

typedef struct {
    uint16_t type;
    uint8_t  data[SS_MAX_EXT_DATA];
    size_t   data_len;
} ss_ext_entry_t;

/* Fisher-Yates shuffle for extension order randomization (Chrome 110+) */
static void ss_shuffle_extensions(ss_ext_entry_t *exts, int count) {
    for (int i = count - 1; i > 0; i--) {
        uint32_t r;
        moor_crypto_random((uint8_t *)&r, sizeof(r));
        int j = (int)(r % (uint32_t)(i + 1));
        ss_ext_entry_t tmp = exts[i];
        exts[i] = exts[j];
        exts[j] = tmp;
    }
}

/* Helper: put uint16 big-endian into buffer */
static inline void ss_put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v);
}

/* Build TLS 1.3 ClientHello matching Chrome's JA4 fingerprint.
 * session_id = HMAC(node_id, client_random) for probe resistance.
 * eph_sk_out receives the ephemeral secret key. */
static int ss_build_client_hello(uint8_t *buf, size_t buf_len, const char *sni,
                                  size_t *out_len, uint8_t eph_sk_out[32],
                                  const uint8_t node_id[32]) {
    if (buf_len < 2560) return -1;

    size_t sni_len = strlen(sni);
    if (sni_len > 253) sni_len = 253;

    uint8_t body[2048];
    size_t pos = 0;

    /* client_version = TLS 1.2 (TLS 1.3 via supported_versions) */
    body[pos++] = 0x03;
    body[pos++] = 0x03;

    /* client_random (32 bytes) */
    moor_crypto_random(body + pos, 32);
    uint8_t *client_random = body + pos;
    pos += 32;

    /* session_id = HMAC(node_id, client_random)[:32] for probing defense */
    body[pos++] = 32; /* session_id length */
    if (node_id && !sodium_is_zero(node_id, 32)) {
        moor_crypto_hash_keyed(body + pos, client_random, 32, node_id);
    } else {
        moor_crypto_random(body + pos, 32);
    }
    pos += 32;

    /* Generate GREASE value for this connection (reused across fields) */
    uint16_t grease_cipher = ss_random_grease();
    uint16_t grease_ext1   = ss_random_grease();
    uint16_t grease_ext2   = ss_random_grease();
    uint16_t grease_group  = ss_random_grease();
    uint16_t grease_ver    = ss_random_grease();

    /* cipher_suites: 1 GREASE + 15 Chrome suites = 16 total = 32 bytes */
    uint16_t cs_bytes = (uint16_t)((1 + CHROME_CIPHER_COUNT) * 2);
    ss_put16(body + pos, cs_bytes); pos += 2;
    ss_put16(body + pos, grease_cipher); pos += 2;
    for (int i = 0; i < CHROME_CIPHER_COUNT; i++) {
        ss_put16(body + pos, chrome_ciphers[i]); pos += 2;
    }

    /* compression_methods: null only */
    body[pos++] = 0x01;
    body[pos++] = 0x00;

    /* ---- Build all extensions as (type, data, len) triples ---- */
    ss_ext_entry_t exts[SS_MAX_EXTENSIONS];
    int ext_count = 0;

    /* Generate Elligator2 ephemeral keypair: repr goes on wire, sk stays local */
    uint8_t eph_repr[32];
    ss_keygen_ct(eph_repr, eph_sk_out);

    /* Ext 0: SNI (0x0000) */
    {
        ss_ext_entry_t *e = &exts[ext_count++];
        e->type = 0x0000;
        size_t p = 0;
        uint16_t list_len = (uint16_t)(sni_len + 3);
        ss_put16(e->data + p, list_len); p += 2;
        e->data[p++] = 0x00; /* host_name */
        ss_put16(e->data + p, (uint16_t)sni_len); p += 2;
        memcpy(e->data + p, sni, sni_len); p += sni_len;
        e->data_len = p;
    }

    /* Ext 1: status_request (0x0005) - OCSP stapling */
    {
        ss_ext_entry_t *e = &exts[ext_count++];
        e->type = 0x0005;
        /* status_type=ocsp(1), responder_id_list_len=0, request_extensions_len=0 */
        e->data[0] = 0x01;
        e->data[1] = 0x00; e->data[2] = 0x00; /* responder_id_list length */
        e->data[3] = 0x00; e->data[4] = 0x00; /* request_extensions length */
        e->data_len = 5;
    }

    /* Ext 2: supported_groups (0x000a) - GREASE + x25519 + secp256r1 + secp384r1 */
    {
        ss_ext_entry_t *e = &exts[ext_count++];
        e->type = 0x000a;
        size_t p = 0;
        uint16_t list_len = 4 * 2; /* 4 groups: GREASE + 3 real */
        ss_put16(e->data + p, list_len); p += 2;
        ss_put16(e->data + p, grease_group); p += 2;
        ss_put16(e->data + p, 0x001d); p += 2; /* x25519 */
        ss_put16(e->data + p, 0x0017); p += 2; /* secp256r1 */
        ss_put16(e->data + p, 0x0018); p += 2; /* secp384r1 */
        e->data_len = p;
    }

    /* Ext 3: ec_point_formats (0x000b) - uncompressed(0) */
    {
        ss_ext_entry_t *e = &exts[ext_count++];
        e->type = 0x000b;
        e->data[0] = 0x01; /* length */
        e->data[1] = 0x00; /* uncompressed */
        e->data_len = 2;
    }

    /* Ext 4: signature_algorithms (0x000d) - 8 algorithms in Chrome's order */
    {
        ss_ext_entry_t *e = &exts[ext_count++];
        e->type = 0x000d;
        size_t p = 0;
        uint16_t list_len = CHROME_SIGALG_COUNT * 2;
        ss_put16(e->data + p, list_len); p += 2;
        for (int i = 0; i < CHROME_SIGALG_COUNT; i++) {
            ss_put16(e->data + p, chrome_sigalgs[i]); p += 2;
        }
        e->data_len = p;
    }

    /* Ext 5: ALPN (0x0010) - h2, http/1.1 */
    {
        ss_ext_entry_t *e = &exts[ext_count++];
        e->type = 0x0010;
        size_t p = 0;
        /* ALPN list: [len:2] [len:1 "h2"] [len:1 "http/1.1"] */
        uint16_t alpn_list_len = 1 + 2 + 1 + 8; /* 12 */
        ss_put16(e->data + p, alpn_list_len); p += 2;
        e->data[p++] = 0x02; /* h2 length */
        e->data[p++] = 'h'; e->data[p++] = '2';
        e->data[p++] = 0x08; /* http/1.1 length */
        memcpy(e->data + p, "http/1.1", 8); p += 8;
        e->data_len = p;
    }

    /* Ext 6: signed_certificate_timestamp (0x0012) - empty */
    {
        ss_ext_entry_t *e = &exts[ext_count++];
        e->type = 0x0012;
        e->data_len = 0;
    }

    /* Ext 7: padding (0x0015) - pad ClientHello to avoid implementation bugs.
     * We target ~517 bytes total body (before TLS record header) like Chrome.
     * Actual pad length is computed after all other extensions. Placeholder for now. */
    int padding_ext_idx = ext_count;
    {
        ss_ext_entry_t *e = &exts[ext_count++];
        e->type = 0x0015;
        e->data_len = 0; /* will be filled in after sizing */
    }

    /* Ext 8: extended_master_secret (0x0017) - empty */
    {
        ss_ext_entry_t *e = &exts[ext_count++];
        e->type = 0x0017;
        e->data_len = 0;
    }

    /* Ext 9: compress_certificate (0x001b) - brotli(2)
     * Format: algorithms_length(1) + algorithm_ids(N*2)
     * Chrome sends: [02] [00 02] = list is 2 bytes, brotli=0x0002 */
    {
        ss_ext_entry_t *e = &exts[ext_count++];
        e->type = 0x001b;
        size_t p = 0;
        e->data[p++] = 0x02; /* algorithms list length = 2 bytes (1 algorithm) */
        ss_put16(e->data + p, 0x0002); p += 2; /* brotli */
        e->data_len = p;
    }

    /* Ext 10: session_ticket (0x0023) - empty */
    {
        ss_ext_entry_t *e = &exts[ext_count++];
        e->type = 0x0023;
        e->data_len = 0;
    }

    /* Ext 11: supported_versions (0x002b) - GREASE + TLS 1.3 + TLS 1.2 */
    {
        ss_ext_entry_t *e = &exts[ext_count++];
        e->type = 0x002b;
        size_t p = 0;
        e->data[p++] = 0x05; /* 5 bytes of version data: 3 versions * ~2 bytes - wait,
                                 it's a length-prefixed list: len(1) + 3*2 = 7 bytes total */
        /* Correct: list_length(1 byte) = 6 (3 versions * 2 bytes) */
        p = 0;
        e->data[p++] = 0x06; /* 3 versions * 2 bytes = 6 */
        ss_put16(e->data + p, grease_ver); p += 2;
        ss_put16(e->data + p, 0x0304); p += 2; /* TLS 1.3 */
        ss_put16(e->data + p, 0x0303); p += 2; /* TLS 1.2 */
        e->data_len = p;
    }

    /* Ext 12: psk_key_exchange_modes (0x002d) - psk_dhe_ke(1) */
    {
        ss_ext_entry_t *e = &exts[ext_count++];
        e->type = 0x002d;
        e->data[0] = 0x01; /* length */
        e->data[1] = 0x01; /* psk_dhe_ke */
        e->data_len = 2;
    }

    /* Ext 13: key_share (0x0033) - Chrome 130+: GREASE + X25519Kyber768 + x25519
     * #2: Chrome 130 sends a PQ hybrid key share (X25519Kyber768Draft00 = 0x6399)
     * alongside the traditional x25519 share.  The Kyber768 share is 1216 bytes
     * (32 x25519 + 1184 Kyber768 pk).  We send random bytes for the Kyber768
     * portion since we only use the x25519 DH -- the PQ key share is purely
     * for JA4 fingerprint matching, not actual PQ key exchange (that happens
     * at the circuit layer via Kyber768 KEM). */
    {
        ss_ext_entry_t *e = &exts[ext_count++];
        e->type = 0x0033;
        size_t p = 0;
        /* Chrome 130 key_shares:
         *   GREASE share: group(2) + len(2) + key(1) = 5 bytes
         *   X25519Kyber768: group(2) + len(2) + key(1216) = 1220 bytes
         *   x25519: group(2) + len(2) + key(32) = 36 bytes
         * Total shares = 5 + 1220 + 36 = 1261 bytes
         * But this makes ClientHello >1300 bytes which is fine (Chrome 130 does too).
         *
         * NOTE: SS_MAX_EXT_DATA must be large enough.  We'll use a separate
         * buffer and write directly since 1261 > SS_MAX_EXT_DATA(300). */
        /* For data >300 bytes, we build the key_share in-place.
         * Since exts[].data is only 300 bytes, we skip the PQ share in the
         * extension builder and instead add it when serializing.
         * Actually, let's just increase the buffer and keep it simple. */

        /* Chrome 130+: GREASE(5) + X25519Kyber768(1220) + x25519(36) = 1261 bytes.
         * The X25519Kyber768Draft00 (group 0x6399) share is 1216 bytes:
         * 32 bytes x25519 + 1184 bytes Kyber768 public key.
         * We fill it with random — only the standalone x25519 share is used for DH.
         * The PQ key exchange happens at MOOR's circuit layer, not TLS. */

        /* GREASE key_share entry */
        ss_put16(e->data + p, grease_group); p += 2;
        ss_put16(e->data + p, 0x0001); p += 2; /* 1 byte key */
        e->data[p++] = 0x00; /* dummy key byte */

        /* X25519Kyber768Draft00 key_share entry (decorative — matches Chrome 130) */
        ss_put16(e->data + p, 0x11ec); p += 2; /* X25519MLKEM768 (Chrome 131+) */
        ss_put16(e->data + p, 1216); p += 2;   /* 1216 bytes */
        moor_crypto_random(e->data + p, 1216); p += 1216;

        /* x25519 key_share entry: Elligator2 representative on wire */
        ss_put16(e->data + p, 0x001d); p += 2; /* x25519 */
        ss_put16(e->data + p, 0x0020); p += 2; /* 32 bytes */
        memcpy(e->data + p, eph_repr, 32); p += 32;

        /* Total shares = 5 + 1220 + 36 = 1261 bytes */
        /* Prepend the total client_shares_length */
        memmove(e->data + 2, e->data, p);
        ss_put16(e->data, (uint16_t)p); /* shares_len */
        p += 2;
        e->data_len = p;
    }

    /* Ext 14: encrypted_client_hello / ECH GREASE (0xfe0d)
     * #2: Chrome 130+ sends an ECH GREASE extension to make ECH deployment
     * look normal even before servers support it.  This is random bytes
     * that look like a real ECH payload.  Without this extension, the
     * JA4 hash won't match Chrome 130. */
    {
        ss_ext_entry_t *e = &exts[ext_count++];
        e->type = 0xfe0d;
        size_t p = 0;
        /* ECH GREASE format: type(1) + KDF_id(2) + AEAD_id(2) + config_id(1)
         * + enc_len(2) + enc(32) + payload_len(2) + payload(N) */
        e->data[p++] = 0x00; /* ECH client hello type: outer */
        ss_put16(e->data + p, 0x0001); p += 2; /* HKDF-SHA256 */
        ss_put16(e->data + p, 0x0001); p += 2; /* AEAD-AES-128-GCM */
        moor_crypto_random(e->data + p, 1); p += 1; /* random config_id */
        ss_put16(e->data + p, 0x0020); p += 2; /* enc length = 32 */
        moor_crypto_random(e->data + p, 32); p += 32; /* random enc */
        uint8_t ech_rand; moor_crypto_random(&ech_rand, 1);
        uint16_t payload_len = 200 + (ech_rand % 56); /* 200-255 bytes */
        ss_put16(e->data + p, payload_len); p += 2;
        moor_crypto_random(e->data + p, payload_len); p += payload_len;
        e->data_len = p;
    }

    /* Ext 15: application_settings/ALPS (0x44cd) - Chrome 134+ new code point */
    {
        ss_ext_entry_t *e = &exts[ext_count++];
        e->type = 0x44cd;
        size_t p = 0;
        ss_put16(e->data + p, 0x0002); p += 2; /* length */
        e->data[p++] = 'h'; e->data[p++] = '2';
        e->data_len = p;
    }

    /* Ext 16: renegotiation_info (0xff01) - empty */
    {
        ss_ext_entry_t *e = &exts[ext_count++];
        e->type = 0xff01;
        e->data[0] = 0x00; /* renegotiated_connection length = 0 */
        e->data_len = 1;
    }

    /* Ext: pre_shared_key (0x0029) -- conditional: only on "resumed" connections.
     * Real browsers only send PSK when they have a cached session ticket from a
     * prior visit. First connection to an SNI has no ticket. Sending PSK on
     * every first connection is a fingerprint.
     * Track previously-used SNIs in a simple static cache. */
    int psk_ext_idx = -1;
    {
        #define SS_PSK_SNI_CACHE_SIZE 64
        static char psk_sni_cache[SS_PSK_SNI_CACHE_SIZE][128];
        static int psk_sni_count = 0;
        static pthread_mutex_t psk_mutex = PTHREAD_MUTEX_INITIALIZER;

        int seen_before = 0;
        pthread_mutex_lock(&psk_mutex);
        for (int s = 0; s < psk_sni_count; s++) {
            if (strcmp(psk_sni_cache[s], sni) == 0) { seen_before = 1; break; }
        }
        if (!seen_before && psk_sni_count < SS_PSK_SNI_CACHE_SIZE) {
            snprintf(psk_sni_cache[psk_sni_count++], 128, "%s", sni);
        }
        pthread_mutex_unlock(&psk_mutex);

        if (seen_before) {
            /* "Resumed" connection — include fake PSK like a real browser would */
            psk_ext_idx = ext_count;
            ss_ext_entry_t *e = &exts[ext_count++];
            e->type = 0x0029;
            size_t p = 0;
            uint8_t psk_rand; moor_crypto_random(&psk_rand, 1);
            uint16_t ticket_len = 192 + (psk_rand % 64);
            uint16_t identities_len = 2 + ticket_len + 4;
            ss_put16(e->data + p, identities_len); p += 2;
            ss_put16(e->data + p, ticket_len); p += 2;
            moor_crypto_random(e->data + p, ticket_len); p += ticket_len;
            moor_crypto_random(e->data + p, 4); p += 4;
            ss_put16(e->data + p, 33); p += 2;
            e->data[p++] = 32;
            moor_crypto_random(e->data + p, 32); p += 32;
            e->data_len = p;
        }
    }

    /* GREASE extensions (1-2 random, with empty data) */
    {
        ss_ext_entry_t *e = &exts[ext_count++];
        e->type = grease_ext1;
        /* Chrome sends GREASE extension with 1-byte zero data */
        e->data[0] = 0x00;
        e->data_len = 1;
    }
    {
        /* 50% chance of a second GREASE extension */
        uint8_t coin;
        moor_crypto_random(&coin, 1);
        if (coin & 1) {
            /* Make sure it's different from grease_ext1 */
            while (grease_ext2 == grease_ext1)
                grease_ext2 = ss_random_grease();
            ss_ext_entry_t *e = &exts[ext_count++];
            e->type = grease_ext2;
            e->data[0] = 0x00;
            e->data_len = 1;
        }
    }

    /* ---- Compute padding extension size ----
     * Chrome pads ClientHello to avoid triggering server bugs with certain sizes.
     * We target total handshake body size ~512 bytes (the standard Chrome target).
     * Calculate current size without padding, then fill to target. */
    {
        /* Estimate total extensions size without padding */
        size_t ext_bytes = 0;
        for (int i = 0; i < ext_count; i++) {
            if (i == padding_ext_idx) continue;
            ext_bytes += 4 + exts[i].data_len; /* type(2) + len(2) + data */
        }
        /* Body so far: version(2) + random(32) + session_id_len(1) + session_id(32)
         *            + cipher_suites_len(2) + cipher_suites(32) + comp(2)
         *            + ext_total_len(2) + ext_bytes + padding_overhead(4) */
        size_t body_so_far = 2 + 32 + 1 + 32 + 2 + cs_bytes + 2 + 2 + ext_bytes + 4;
        /* Target: 512 bytes of body (inside handshake header).
         * This makes total ClientHello = 5(record) + 4(hs header) + 512 = 521 bytes,
         * typical for Chrome. */
        size_t target_body = 512;
        if (body_so_far < target_body) {
            size_t pad_needed = target_body - body_so_far;
            if (pad_needed > SS_MAX_EXT_DATA) pad_needed = SS_MAX_EXT_DATA;
            memset(exts[padding_ext_idx].data, 0, pad_needed);
            exts[padding_ext_idx].data_len = pad_needed;
        }
    }

    /* ---- Shuffle extensions (Fisher-Yates) for Chrome 110+ behavior ----
     * JA4 sorts extensions before hashing, so order doesn't affect the fingerprint.
     * #6: pre_shared_key (0x0029) MUST be last per RFC 8446 4.2.11.
     * If PSK is present, remove it before shuffle, then append after. */
    if (psk_ext_idx >= 0) {
        ss_ext_entry_t psk_ext_saved = exts[psk_ext_idx];
        exts[psk_ext_idx] = exts[ext_count - 1];
        int shuffle_count = ext_count - 1;
        ss_shuffle_extensions(exts, shuffle_count);
        exts[shuffle_count] = psk_ext_saved; /* PSK goes last */
    } else {
        ss_shuffle_extensions(exts, ext_count);
    }

    /* ---- Serialize extensions into body ---- */
    size_t ext_start = pos;
    pos += 2; /* placeholder for total extensions length */

    for (int i = 0; i < ext_count; i++) {
        ss_put16(body + pos, exts[i].type); pos += 2;
        ss_put16(body + pos, (uint16_t)exts[i].data_len); pos += 2;
        if (exts[i].data_len > 0) {
            memcpy(body + pos, exts[i].data, exts[i].data_len);
            pos += exts[i].data_len;
        }
    }

    /* Write extensions length */
    uint16_t ext_len = (uint16_t)(pos - ext_start - 2);
    ss_put16(body + ext_start, ext_len);

    /* Handshake wrapper: type(1) + length(3) + body */
    size_t hs_len = 1 + 3 + pos;
    uint8_t hs_msg[2560];
    hs_msg[0] = TLS_HS_CLIENT_HELLO;
    hs_msg[1] = 0;
    hs_msg[2] = (uint8_t)(pos >> 8);
    hs_msg[3] = (uint8_t)(pos);
    memcpy(hs_msg + 4, body, pos);

    /* TLS record wrapper */
    ss_tls_record_header(buf, TLS_HANDSHAKE, (uint16_t)(hs_len));
    memcpy(buf + TLS_RECORD_HEADER, hs_msg, 4 + pos);
    *out_len = TLS_RECORD_HEADER + 4 + pos;
    return 0;
}

/* Build ServerHello + ChangeCipherSpec with Elligator2-representable key */
static int ss_build_server_hello(uint8_t *buf, size_t buf_len, size_t *out_len,
                                  uint8_t eph_sk_out[32],
                                  const uint8_t client_session_id[32]) {
    if (buf_len < 300) return -1;

    uint8_t body[512];  /* was 160, room for future extensions */
    size_t pos = 0;

    body[pos++] = 0x03; body[pos++] = 0x03; /* version */
    moor_crypto_random(body + pos, 32);       /* random */
    pos += 32;

    /* Echo client session_id */
    body[pos++] = 32;
    memcpy(body + pos, client_session_id, 32);
    pos += 32;

    /* cipher_suite: TLS_CHACHA20_POLY1305_SHA256 */
    body[pos++] = (uint8_t)(TLS_CHACHA20_POLY1305_SHA256 >> 8);
    body[pos++] = (uint8_t)(TLS_CHACHA20_POLY1305_SHA256);

    /* compression = null */
    body[pos++] = 0x00;

    /* Extensions: supported_versions + key_share */
    uint16_t ext_len = 6 + 40;
    body[pos++] = (uint8_t)(ext_len >> 8);
    body[pos++] = (uint8_t)(ext_len);
    /* supported_versions */
    body[pos++] = 0x00; body[pos++] = 0x2b;
    body[pos++] = 0x00; body[pos++] = 0x02;
    body[pos++] = 0x03; body[pos++] = 0x04;

    /* key_share: Elligator2 representative on wire */
    body[pos++] = 0x00; body[pos++] = 0x33;
    body[pos++] = 0x00; body[pos++] = 0x24;
    body[pos++] = 0x00; body[pos++] = 0x1d;
    body[pos++] = 0x00; body[pos++] = 0x20;
    if (pos + 32 > sizeof(body)) return -1;
    uint8_t eph_repr[32];
    ss_keygen_ct(eph_repr, eph_sk_out);
    memcpy(body + pos, eph_repr, 32);
    pos += 32;

    /* Handshake wrapper */
    uint8_t hs[4 + 512];
    hs[0] = TLS_HS_SERVER_HELLO;
    hs[1] = 0;
    hs[2] = (uint8_t)(pos >> 8);
    hs[3] = (uint8_t)(pos);
    memcpy(hs + 4, body, pos);

    /* TLS record: ServerHello */
    size_t total = 0;
    ss_tls_record_header(buf, TLS_HANDSHAKE, (uint16_t)(4 + pos));
    memcpy(buf + TLS_RECORD_HEADER, hs, 4 + pos);
    total = TLS_RECORD_HEADER + 4 + pos;

    /* TLS record: ChangeCipherSpec */
    ss_tls_record_header(buf + total, TLS_CHANGE_CIPHER_SPEC, 1);
    buf[total + TLS_RECORD_HEADER] = 0x01;
    total += TLS_RECORD_HEADER + 1;

    *out_len = total;
    return 0;
}

/* Extract x25519 public key from ClientHello body's key_share extension.
 * The wire bytes are an Elligator2 representative; this function recovers
 * the real Curve25519 public key via the direct map.
 * Handles GREASE key_share entries by iterating through all shares to find x25519. */
static int ss_extract_key_share_ch(const uint8_t *body, size_t body_len,
                                    uint8_t pk_out[32]) {
    size_t pos = 2 + 32; /* version + random */
    if (pos >= body_len) return -1;
    size_t sid_len = body[pos]; pos += 1 + sid_len;
    if (pos + 2 > body_len) return -1;
    uint16_t cs_len = ((uint16_t)body[pos] << 8) | body[pos + 1]; pos += 2 + cs_len;
    if (pos >= body_len) return -1;
    size_t comp_len = body[pos]; pos += 1 + comp_len;
    if (pos + 2 > body_len) return -1;
    uint16_t ext_total = ((uint16_t)body[pos] << 8) | body[pos + 1]; pos += 2;
    size_t ext_end = pos + ext_total;
    if (ext_end > body_len) return -1;

    while (pos + 4 <= ext_end) {
        uint16_t ext_type = ((uint16_t)body[pos] << 8) | body[pos + 1];
        uint16_t ext_len  = ((uint16_t)body[pos + 2] << 8) | body[pos + 3];
        pos += 4;
        if (ext_type == 0x0033 && ext_len >= 4) {
            /* key_share data: client_shares_length(2) + share entries */
            size_t ks_start = pos;
            size_t ks_end = pos + ext_len;
            if (ks_end > ext_end) { pos += ext_len; continue; }
            uint16_t shares_len = ((uint16_t)body[ks_start] << 8) | body[ks_start + 1];
            size_t sp = ks_start + 2;
            size_t shares_end = sp + shares_len;
            if (shares_end > ks_end) shares_end = ks_end;
            /* Iterate through key share entries to find x25519 (0x001d) */
            while (sp + 4 <= shares_end) {
                uint16_t group   = ((uint16_t)body[sp] << 8) | body[sp + 1];
                uint16_t key_len = ((uint16_t)body[sp + 2] << 8) | body[sp + 3];
                sp += 4;
                if (group == 0x001d && key_len == 32 && sp + 32 <= shares_end) {
                    /* Wire bytes are Elligator2 representative -- decode to real pk.
                     * Clear the two high random bits before decoding. */
                    uint8_t repr[32];
                    memcpy(repr, body + sp, 32);
                    repr[31] &= 0x3f;
                    moor_elligator2_representative_to_key(pk_out, repr);
                    return 0;
                }
                sp += key_len;
            }
        }
        pos += ext_len;
    }
    return -1;
}

/* Extract x25519 public key from ServerHello body's key_share extension.
 * Wire bytes are Elligator2 representative; decoded via direct map. */
static int ss_extract_key_share_sh(const uint8_t *body, size_t body_len,
                                    uint8_t pk_out[32]) {
    size_t pos = 2 + 32; /* version + random */
    if (pos >= body_len) return -1;
    size_t sid_len = body[pos]; pos += 1 + sid_len;
    pos += 2 + 1; /* cipher_suite + compression */
    if (pos + 2 > body_len) return -1;
    uint16_t ext_total = ((uint16_t)body[pos] << 8) | body[pos + 1]; pos += 2;
    size_t ext_end = pos + ext_total;
    if (ext_end > body_len) return -1;

    while (pos + 4 <= ext_end) {
        uint16_t ext_type = ((uint16_t)body[pos] << 8) | body[pos + 1];
        uint16_t ext_len  = ((uint16_t)body[pos + 2] << 8) | body[pos + 3];
        pos += 4;
        if (ext_type == 0x0033 && ext_len >= 36 && pos + 36 <= ext_end) {
            /* Verify key_share group is x25519 (0x001d) before accepting (#R1-A2) */
            uint16_t group = ((uint16_t)body[pos] << 8) | body[pos + 1];
            if (group != 0x001d) return -1;
            uint16_t key_len = ((uint16_t)body[pos + 2] << 8) | body[pos + 3];
            if (key_len == 32) {
                /* Wire bytes are Elligator2 representative -- decode to real pk */
                uint8_t repr[32];
                memcpy(repr, body + pos + 4, 32);
                repr[31] &= 0x3f;
                moor_elligator2_representative_to_key(pk_out, repr);
                return 0;
            }
        }
        pos += ext_len;
    }
    return -1;
}

/* ================================================================
 * Key derivation -- double-DH with inner/outer split
 *
 * Outer keys: HKDF(DH(eph,eph) || DH(eph,identity) || BLAKE2b(transcript))
 * Inner keys: KDF(outer_material, "shtstm!", subkeys 0-3)
 * ================================================================ */
static int ss_derive_keys(shitstorm_state_t *st,
                           const uint8_t our_eph_sk[32],
                           const uint8_t their_eph_pk[32],
                           const uint8_t *static_dh,  /* 32 bytes or NULL */
                           int is_initiator,
                           const uint8_t *transcript,
                           size_t transcript_len) {
    /* Low-order point rejection is handled internally by libsodium's
     * crypto_scalarmult_curve25519 (returns -1 for invalid points
     * since libsodium 1.0.18+).  No additional check needed.
     * The previous random-scalar test was dead code that wasted entropy. */

    /* Ephemeral DH */
    uint8_t eph_shared[32];
    if (moor_crypto_dh(eph_shared, our_eph_sk, their_eph_pk) != 0)
        return -1;

    /* Transcript hash */
    uint8_t transcript_hash[32];
    crypto_generichash_blake2b(transcript_hash, 32,
                                transcript, transcript_len, NULL, 0);

    /* HKDF input = eph_shared(32) [+ static_dh(32)] + transcript_hash(32) */
    uint8_t hkdf_input[96];
    size_t hkdf_len = 0;
    memcpy(hkdf_input + hkdf_len, eph_shared, 32); hkdf_len += 32;
    sodium_memzero(eph_shared, 32);
    if (static_dh) {
        memcpy(hkdf_input + hkdf_len, static_dh, 32); hkdf_len += 32;
    }
    memcpy(hkdf_input + hkdf_len, transcript_hash, 32); hkdf_len += 32;

    /* Derive 64 bytes of outer key material */
    uint8_t outer_km[64];
    static const uint8_t outer_label[] = "shitstorm-outer-keys";
    crypto_generichash_blake2b(outer_km, 64, hkdf_input, hkdf_len,
                                outer_label, sizeof(outer_label) - 1);
    sodium_memzero(hkdf_input, sizeof(hkdf_input));
    sodium_memzero(transcript_hash, 32);

    /* Outer send/recv keys (direction-dependent) */
    if (is_initiator) {
        memcpy(st->outer_send_key, outer_km, 32);
        memcpy(st->outer_recv_key, outer_km + 32, 32);
    } else {
        memcpy(st->outer_recv_key, outer_km, 32);
        memcpy(st->outer_send_key, outer_km + 32, 32);
    }
    st->outer_send_nonce = 0;
    st->outer_recv_nonce = 0;

    /* Derive inner keys from outer key material using KDF with context "shtstm!" */
    uint8_t inner_base[32];
    crypto_generichash_blake2b(inner_base, 32, outer_km, 64,
                                (const uint8_t *)"shitstorm-inner", 15);
    sodium_memzero(outer_km, 64);

    /* 4 inner subkeys: inner_send, inner_recv, header_send, header_recv */
    moor_crypto_kdf(st->inner_send_key, 32, inner_base,
                    is_initiator ? 0 : 1, "shtstm!");
    moor_crypto_kdf(st->inner_recv_key, 32, inner_base,
                    is_initiator ? 1 : 0, "shtstm!");
    moor_crypto_kdf(st->header_send_key, 32, inner_base,
                    is_initiator ? 2 : 3, "shtstm!");
    moor_crypto_kdf(st->header_recv_key, 32, inner_base,
                    is_initiator ? 3 : 2, "shtstm!");
    sodium_memzero(inner_base, 32);

    st->inner_send_nonce = 0;
    st->inner_recv_nonce = 0;
    st->recv_len = 0;
    st->records_sent = 0;
    st->records_received = 0;
    st->rekey_epoch = 0;
    st->rekey_recv_epoch = 0;
    st->h2_sent_preface = 0;
    st->h2_stream_id = 1;  /* client-initiated streams are odd */

    return 0;
}

/* ================================================================
 * Key rotation (#5): ratchet all keys every SS_REKEY_INTERVAL records.
 *
 * new_key = BLAKE2b(old_key || epoch_counter, "shitstorm-rekey")
 * Nonces reset to 0 after ratchet.  Both sides ratchet independently
 * at the same record count, so keys stay in sync without signaling.
 * ================================================================ */
static void ss_maybe_rekey(shitstorm_state_t *st) {
    if (st->records_sent > 0 &&
        st->records_sent % SS_REKEY_INTERVAL == 0) {
        st->rekey_epoch++;
        uint8_t ratchet_input[36]; /* key(32) + epoch(4) */
        static const uint8_t rekey_label[] = "shitstorm-rekey";

        /* Ratchet outer send key — nonces keep incrementing (no reset).
         * AEAD requires nonce uniqueness per key; since the key changed,
         * nonce continuity is safe and avoids the handshake-offset bug
         * where sender/receiver reset at different record boundaries. */
        memcpy(ratchet_input, st->outer_send_key, 32);
        ratchet_input[32] = (uint8_t)(st->rekey_epoch);
        ratchet_input[33] = (uint8_t)(st->rekey_epoch >> 8);
        ratchet_input[34] = (uint8_t)(st->rekey_epoch >> 16);
        ratchet_input[35] = (uint8_t)(st->rekey_epoch >> 24);
        crypto_generichash_blake2b(st->outer_send_key, 32,
                                    ratchet_input, 36, rekey_label, 15);

        /* Ratchet inner send key */
        memcpy(ratchet_input, st->inner_send_key, 32);
        ratchet_input[32] = (uint8_t)(st->rekey_epoch);
        ratchet_input[33] = (uint8_t)(st->rekey_epoch >> 8);
        ratchet_input[34] = (uint8_t)(st->rekey_epoch >> 16);
        ratchet_input[35] = (uint8_t)(st->rekey_epoch >> 24);
        crypto_generichash_blake2b(st->inner_send_key, 32,
                                    ratchet_input, 36, rekey_label, 15);

        /* Ratchet header key */
        memcpy(ratchet_input, st->header_send_key, 32);
        crypto_generichash_blake2b(st->header_send_key, 32,
                                    ratchet_input, 36, rekey_label, 15);

        sodium_memzero(ratchet_input, sizeof(ratchet_input));
        LOG_DEBUG("shitstorm: key rotation at record %llu (epoch %u)",
                  (unsigned long long)st->records_sent, st->rekey_epoch);
    }
}

/* Receiver-side rekey: mirror sender's rotation using records_received.
 * Uses explicit rekey_recv_epoch counter (same as sender uses rekey_epoch)
 * so both sides always agree on the epoch value regardless of what
 * record types are/aren't counted. */
static void ss_maybe_rekey_recv(shitstorm_state_t *st) {
    if (st->records_received > 0 &&
        st->records_received % SS_REKEY_INTERVAL == 0) {
        st->rekey_recv_epoch++;
        uint32_t epoch = st->rekey_recv_epoch;
        uint8_t ratchet_input[36];
        static const uint8_t rekey_label[] = "shitstorm-rekey";

        memcpy(ratchet_input, st->outer_recv_key, 32);
        ratchet_input[32] = (uint8_t)(epoch);
        ratchet_input[33] = (uint8_t)(epoch >> 8);
        ratchet_input[34] = (uint8_t)(epoch >> 16);
        ratchet_input[35] = (uint8_t)(epoch >> 24);
        crypto_generichash_blake2b(st->outer_recv_key, 32,
                                    ratchet_input, 36, rekey_label, 15);

        memcpy(ratchet_input, st->inner_recv_key, 32);
        ratchet_input[32] = (uint8_t)(epoch);
        ratchet_input[33] = (uint8_t)(epoch >> 8);
        ratchet_input[34] = (uint8_t)(epoch >> 16);
        ratchet_input[35] = (uint8_t)(epoch >> 24);
        crypto_generichash_blake2b(st->inner_recv_key, 32,
                                    ratchet_input, 36, rekey_label, 15);

        memcpy(ratchet_input, st->header_recv_key, 32);
        crypto_generichash_blake2b(st->header_recv_key, 32,
                                    ratchet_input, 36, rekey_label, 15);

        sodium_memzero(ratchet_input, sizeof(ratchet_input));
        LOG_DEBUG("shitstorm: recv key rotation at record %llu (epoch %u)",
                  (unsigned long long)st->records_received, epoch);
    }
}

/* ================================================================
 * Handshake: send/recv a Finished message inside a TLS app data record.
 *
 * The Finished proves the client holds derived keys.  It is a single
 * TLS Application Data record containing:
 *   OUTER_AEAD(outer_key, SHITSTORM_FINISHED_MAGIC)
 *
 * This is NOT the inner double-encryption used for post-handshake data --
 * it is a simple AEAD to confirm key agreement before data flows.
 * ================================================================ */
static int ss_send_finished(int fd, shitstorm_state_t *st) {
    /* Build AEAD-encrypted Finished magic */
    uint8_t nonce[12];
    memset(nonce, 0, 12);
    for (int i = 0; i < 8; i++)
        nonce[4 + i] = (uint8_t)(st->outer_send_nonce >> (i * 8));

    if (st->outer_send_nonce == UINT64_MAX) return -1;

    uint8_t ct[SHITSTORM_FINISHED_MAGIC_LEN + 16]; /* +16 for Poly1305 tag */
    unsigned long long ct_len;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        ct, &ct_len,
        SHITSTORM_FINISHED_MAGIC, SHITSTORM_FINISHED_MAGIC_LEN,
        NULL, 0, NULL, nonce, st->outer_send_key);
    st->outer_send_nonce++;

    /* Wrap in TLS Application Data record */
    uint8_t hdr[TLS_RECORD_HEADER];
    ss_tls_record_header(hdr, TLS_APPLICATION_DATA, (uint16_t)ct_len);
    if (ss_send_all(fd, hdr, TLS_RECORD_HEADER) != 0) return -1;
    if (ss_send_all(fd, ct, (size_t)ct_len) != 0) return -1;

    return 0;
}

static int ss_recv_finished(int fd, shitstorm_state_t *st) {
    /* Read TLS record header */
    uint8_t hdr[TLS_RECORD_HEADER];
    if (ss_recv_all(fd, hdr, TLS_RECORD_HEADER) != 0) return -1;
    if (hdr[0] != TLS_APPLICATION_DATA) return -1;
    uint16_t rec_len = ((uint16_t)hdr[3] << 8) | hdr[4];
    if (rec_len < SHITSTORM_FINISHED_MAGIC_LEN + 16 || rec_len > 256) return -1;

    uint8_t ct[256];
    if (ss_recv_all(fd, ct, rec_len) != 0) return -1;

    /* Decrypt */
    uint8_t nonce[12];
    memset(nonce, 0, 12);
    for (int i = 0; i < 8; i++)
        nonce[4 + i] = (uint8_t)(st->outer_recv_nonce >> (i * 8));

    if (st->outer_recv_nonce == UINT64_MAX) return -1;

    uint8_t pt[256];
    unsigned long long pt_len;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            pt, &pt_len, NULL,
            ct, rec_len, NULL, 0, nonce, st->outer_recv_key) != 0) {
        LOG_WARN("shitstorm: Finished AEAD verification failed");
        return -1;
    }
    st->outer_recv_nonce++;

    /* Verify magic */
    if (pt_len != SHITSTORM_FINISHED_MAGIC_LEN ||
        sodium_memcmp(pt, SHITSTORM_FINISHED_MAGIC, SHITSTORM_FINISHED_MAGIC_LEN) != 0) {
        LOG_WARN("shitstorm: Finished magic mismatch");
        sodium_memzero(pt, sizeof(pt));
        return -1;
    }
    sodium_memzero(pt, sizeof(pt));
    return 0;
}

/* ================================================================
 * Client handshake
 * ================================================================ */
static int shitstorm_client_handshake(int fd, const void *params,
                                       moor_transport_state_t **state) {
    const moor_shitstorm_client_params_t *p =
        (const moor_shitstorm_client_params_t *)params;

    char sni[256];
    if (p && p->sni[0])
        snprintf(sni, sizeof(sni), "%s", p->sni);
    else
        ss_random_sni(sni, sizeof(sni));

    fprintf(stderr, "\033[33mShitStorm: connecting with SNI '%s'\033[0m\n", sni);
    LOG_INFO("ShitStorm: connecting with SNI '%s'", sni);

    /* 1. Build ClientHello with Elligator2-representable key */
    uint8_t ch_buf[2560];
    size_t ch_len;
    uint8_t our_eph_sk[32];
    if (ss_build_client_hello(ch_buf, sizeof(ch_buf), sni, &ch_len,
                               our_eph_sk, p ? p->identity_pk : NULL) != 0)
        return -1;

    /* 2. Send ClientHello */
    if (ss_send_all(fd, ch_buf, ch_len) != 0) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }

    /* 3. Receive ServerHello record */
    uint8_t sh_buf[1024];
    if (ss_recv_all(fd, sh_buf, TLS_RECORD_HEADER) != 0) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }
    if (sh_buf[0] != TLS_HANDSHAKE) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }
    uint16_t sh_len = ((uint16_t)sh_buf[3] << 8) | sh_buf[4];
    if (sh_len > 400 || sh_len < 40) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }
    if (ss_recv_all(fd, sh_buf + TLS_RECORD_HEADER, sh_len) != 0) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }
    if (sh_buf[TLS_RECORD_HEADER] != TLS_HS_SERVER_HELLO) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }

    /* Extract server ephemeral x25519 pk */
    uint8_t server_eph_pk[32];
    if (ss_extract_key_share_sh(sh_buf + TLS_RECORD_HEADER + 4,
                                 sh_len - 4, server_eph_pk) != 0) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }

    /* Read CCS record */
    uint8_t ccs_buf[8];
    if (ss_recv_all(fd, ccs_buf, TLS_RECORD_HEADER + 1) != 0) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }
    if (ccs_buf[0] != TLS_CHANGE_CIPHER_SPEC) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }

    /* 4. Consume fake encrypted HS records */
    if (ss_recv_fake_encrypted_hs(fd) != 0) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }

    /* 5. Build transcript = CH record || SH record */
    size_t transcript_len = ch_len + TLS_RECORD_HEADER + sh_len;
    uint8_t *transcript = malloc(transcript_len);
    if (!transcript) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }
    memcpy(transcript, ch_buf, ch_len);
    memcpy(transcript + ch_len, sh_buf, TLS_RECORD_HEADER + sh_len);

    /* Compute static-ephemeral DH for MITM resistance:
     * DH(our_eph_sk, curve25519(identity_pk)) */
    uint8_t static_dh[32];
    uint8_t *static_dh_ptr = NULL;
    if (p && !sodium_is_zero(p->identity_pk, 32)) {
        uint8_t node_curve[32];
        if (crypto_sign_ed25519_pk_to_curve25519(node_curve, p->identity_pk) == 0) {
            if (crypto_scalarmult(static_dh, our_eph_sk, node_curve) == 0 &&
                !sodium_is_zero(static_dh, 32))
                static_dh_ptr = static_dh;
            sodium_memzero(node_curve, 32);
        }
    }

    /* 6. Derive outer + inner keys */
    shitstorm_state_t *st = calloc(1, sizeof(shitstorm_state_t));
    if (!st) {
        sodium_memzero(our_eph_sk, 32);
        sodium_memzero(static_dh, 32);
        free(transcript);
        return -1;
    }
    if (ss_derive_keys(st, our_eph_sk, server_eph_pk, static_dh_ptr, 1,
                        transcript, transcript_len) != 0) {
        sodium_memzero(our_eph_sk, 32);
        sodium_memzero(static_dh, 32);
        free(transcript);
        free(st);
        return -1;
    }
    sodium_memzero(our_eph_sk, 32);
    sodium_memzero(static_dh, 32);
    free(transcript);

    /* 7. Send client Finished */
    if (ss_send_finished(fd, st) != 0) {
        sodium_memzero(st, sizeof(*st));
        free(st);
        return -1;
    }

    /* #6: Consume fake NewSessionTicket messages from server */
    if (ss_recv_fake_new_session_tickets(fd, st) != 0) {
        sodium_memzero(st, sizeof(*st));
        free(st);
        return -1;
    }

    *state = (moor_transport_state_t *)st;
    LOG_INFO("shitstorm: client handshake complete");
    return 0;
}

/* Decoy site proxy: forward a non-MOOR connection to a real web server.
 * The client (censor probe or real browser) sees a normal TLS website.
 * This defeats active probing — the bridge is indistinguishable from
 * the decoy site for unauthenticated connections. */
static void ss_proxy_to_decoy(int client_fd, const char *addr, uint16_t port,
                               const uint8_t *ch_hdr, size_t ch_hdr_len,
                               const uint8_t *ch_body, size_t ch_body_len) {
    /* Connect to decoy */
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = inet_addr(addr);

    int decoy_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (decoy_fd < 0) return;

    if (connect(decoy_fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(decoy_fd);
        return;
    }

    /* Forward the ClientHello we already received */
    send(decoy_fd, (const char *)ch_hdr, ch_hdr_len, MSG_NOSIGNAL);
    send(decoy_fd, (const char *)ch_body, ch_body_len, MSG_NOSIGNAL);

    /* Bidirectional relay until one side closes.
     * This runs synchronously — blocks the caller. Acceptable because
     * this is a probe/non-MOOR connection, not real relay traffic. */
    struct pollfd pfds[2];
    pfds[0].fd = client_fd;  pfds[0].events = POLLIN;
    pfds[1].fd = decoy_fd;   pfds[1].events = POLLIN;

    uint8_t relay_buf[4096];
    int running = 1;
    while (running) {
        int pr = poll(pfds, 2, 30000);
        if (pr <= 0) break;
        if (pfds[0].revents & POLLIN) {
            ssize_t n = recv(client_fd, (char *)relay_buf, sizeof(relay_buf), 0);
            if (n <= 0) { running = 0; break; }
            if (send(decoy_fd, (const char *)relay_buf, n, MSG_NOSIGNAL) != n)
                { running = 0; break; }
        }
        if (pfds[1].revents & POLLIN) {
            ssize_t n = recv(decoy_fd, (char *)relay_buf, sizeof(relay_buf), 0);
            if (n <= 0) { running = 0; break; }
            if (send(client_fd, (const char *)relay_buf, n, MSG_NOSIGNAL) != n)
                { running = 0; break; }
        }
        if ((pfds[0].revents | pfds[1].revents) & (POLLHUP | POLLERR))
            running = 0;
    }
    close(decoy_fd);
}

/* ================================================================
 * Server handshake
 * ================================================================ */
static int shitstorm_server_handshake(int fd, const void *params,
                                       moor_transport_state_t **state) {
    const moor_shitstorm_server_params_t *sp =
        (const moor_shitstorm_server_params_t *)params;

    /* 1. Receive ClientHello */
    uint8_t ch_hdr[TLS_RECORD_HEADER];
    if (ss_recv_all(fd, ch_hdr, TLS_RECORD_HEADER) != 0) return -1;
    if (ch_hdr[0] != TLS_HANDSHAKE) return -1;
    uint16_t ch_len = ((uint16_t)ch_hdr[3] << 8) | ch_hdr[4];
    if (ch_len > 2048 || ch_len < 40) return -1;

    uint8_t ch_body[2048];
    if (ss_recv_all(fd, ch_body, ch_len) != 0) return -1;
    if (ch_body[0] != TLS_HS_CLIENT_HELLO) return -1;

    /* Verify session_id = HMAC(identity_pk, client_random) */
    if (sp && !sodium_is_zero(sp->identity_pk, 32)) {
        if (ch_len >= 4 + 2 + 32 + 1 + 32) {
            uint8_t *client_random = ch_body + 4 + 2;
            uint8_t sid_len = ch_body[4 + 34];
            if (sid_len != 32) {
                if (sp->decoy_addr[0] && sp->decoy_port > 0)
                    ss_proxy_to_decoy(fd, sp->decoy_addr, sp->decoy_port,
                                      ch_hdr, TLS_RECORD_HEADER, ch_body, ch_len);
                return -1;
            }
            uint8_t expected_sid[32];
            moor_crypto_hash_keyed(expected_sid, client_random, 32, sp->identity_pk);
            if (sodium_memcmp(expected_sid, ch_body + 4 + 35, 32) != 0) {
                sodium_memzero(expected_sid, 32);
                /* Not a MOOR client — proxy to decoy site instead of
                 * silent drop.  Active probes see a real website. */
                if (sp->decoy_addr[0] && sp->decoy_port > 0) {
                    LOG_INFO("shitstorm: auth failed, proxying to decoy %s:%u",
                             sp->decoy_addr, sp->decoy_port);
                    ss_proxy_to_decoy(fd, sp->decoy_addr, sp->decoy_port,
                                      ch_hdr, TLS_RECORD_HEADER,
                                      ch_body, ch_len);
                }
                return -1;
            }
            sodium_memzero(expected_sid, 32);
        } else {
            if (sp->decoy_addr[0] && sp->decoy_port > 0)
                ss_proxy_to_decoy(fd, sp->decoy_addr, sp->decoy_port,
                                  ch_hdr, TLS_RECORD_HEADER, ch_body, ch_len);
            return -1;
        }
    }

    /* Extract client ephemeral key */
    uint8_t client_eph_pk[32];
    if (ss_extract_key_share_ch(ch_body + 4, ch_len - 4, client_eph_pk) != 0)
        return -1;

    /* 2. Replay cache check */
    if (ss_replay_check(client_eph_pk) != 0) {
        LOG_WARN("shitstorm: replayed client ephemeral key rejected");
        return -1;
    }

    /* Extract client session_id for echo */
    uint8_t client_session_id[32];
    memset(client_session_id, 0, 32);
    if (ch_len >= 4 + 2 + 32 + 1 + 32) {
        uint8_t sid_len = ch_body[4 + 34];
        if (sid_len == 32)
            memcpy(client_session_id, ch_body + 4 + 35, 32);
    }

    /* 3-4. Build and send ServerHello + CCS + fake HS records */
    uint8_t sh_buf[1024];
    size_t sh_out_len;
    uint8_t our_eph_sk[32];
    if (ss_build_server_hello(sh_buf, sizeof(sh_buf), &sh_out_len, our_eph_sk,
                               client_session_id) != 0) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }
    if (ss_send_all(fd, sh_buf, sh_out_len) != 0) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }
    if (ss_send_fake_encrypted_hs(fd) != 0) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }

    /* 5. Build transcript and derive keys */
    uint16_t sh_record_payload = ((uint16_t)sh_buf[3] << 8) | sh_buf[4];
    size_t sh_record_len = TLS_RECORD_HEADER + sh_record_payload;
    size_t transcript_len = (size_t)(TLS_RECORD_HEADER + ch_len) + sh_record_len;
    uint8_t *transcript = malloc(transcript_len);
    if (!transcript) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }
    memcpy(transcript, ch_hdr, TLS_RECORD_HEADER);
    memcpy(transcript + TLS_RECORD_HEADER, ch_body, ch_len);
    memcpy(transcript + TLS_RECORD_HEADER + ch_len, sh_buf, sh_record_len);

    /* Compute static-ephemeral DH for MITM resistance:
     * DH(curve25519(identity_sk), client_eph_pk) */
    uint8_t static_dh[32];
    uint8_t *static_dh_ptr = NULL;
    if (sp && !sodium_is_zero(sp->identity_sk, 64)) {
        uint8_t our_curve_sk[32];
        if (moor_crypto_ed25519_to_curve25519_sk(our_curve_sk, sp->identity_sk) == 0) {
            if (crypto_scalarmult(static_dh, our_curve_sk, client_eph_pk) == 0 &&
                !sodium_is_zero(static_dh, 32))
                static_dh_ptr = static_dh;
            sodium_memzero(our_curve_sk, 32);
        }
    }

    shitstorm_state_t *st = calloc(1, sizeof(shitstorm_state_t));
    if (!st) {
        sodium_memzero(our_eph_sk, 32);
        sodium_memzero(static_dh, 32);
        free(transcript);
        return -1;
    }
    if (ss_derive_keys(st, our_eph_sk, client_eph_pk, static_dh_ptr, 0,
                        transcript, transcript_len) != 0) {
        sodium_memzero(our_eph_sk, 32);
        sodium_memzero(static_dh, 32);
        free(transcript);
        free(st);
        return -1;
    }
    sodium_memzero(our_eph_sk, 32);
    sodium_memzero(static_dh, 32);
    free(transcript);

    /* 6. Receive and verify client Finished */
    if (ss_recv_finished(fd, st) != 0) {
        sodium_memzero(st, sizeof(*st));
        free(st);
        return -1;
    }

    /* #6: Send fake NewSessionTicket messages (server → client).
     * Real TLS 1.3 servers send 1-2 tickets right after handshake. */
    if (ss_send_fake_new_session_tickets(fd, st) != 0) {
        sodium_memzero(st, sizeof(*st));
        free(st);
        return -1;
    }

    *state = (moor_transport_state_t *)st;
    LOG_INFO("shitstorm: server handshake complete");
    return 0;
}

/* ================================================================
 * Post-handshake data transport: double encryption inside TLS records.
 *
 * Wire format per TLS Application Data record:
 *   TLS record header (5 bytes, content_type=0x17)
 *   OUTER AEAD ciphertext:
 *     Plaintext = [obfuscated_len:2] + [INNER AEAD ciphertext]
 *     Where INNER AEAD plaintext = [data] + [random_pad:0-15] + [pad_len:1]
 *     And obfuscated_len = inner_ct_len XOR ChaCha20(header_key, inner_nonce)
 *
 * First record is padded to 1400-1500 bytes to defeat size fingerprinting.
 * ================================================================ */

/* #1 HTTP/2 connection preface + SETTINGS frame.
 * Sent once after handshake to make post-handshake bytes look like h2.
 * Real h2 preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + SETTINGS frame.
 * We send this as the first TLS record's inner payload prefix. */
static const uint8_t H2_PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
#define H2_PREFACE_LEN 24

/* HTTP/2 frame header: length(3) + type(1) + flags(1) + stream_id(4) = 9 bytes */
static void ss_h2_frame_header(uint8_t out[9], uint32_t length, uint8_t type,
                                uint8_t flags, uint32_t stream_id) {
    out[0] = (uint8_t)(length >> 16);
    out[1] = (uint8_t)(length >> 8);
    out[2] = (uint8_t)(length);
    out[3] = type;
    out[4] = flags;
    out[5] = (uint8_t)(stream_id >> 24) & 0x7F; /* MSB reserved */
    out[6] = (uint8_t)(stream_id >> 16);
    out[7] = (uint8_t)(stream_id >> 8);
    out[8] = (uint8_t)(stream_id);
}

/* #6 Fake NewSessionTicket: server sends after handshake.
 * Real TLS 1.3 servers send 1-2 NewSessionTicket messages immediately
 * after the handshake completes.  Without these, the connection is
 * fingerprinted as "never issues tickets" = likely not a real server.
 * We send 2 fake tickets as TLS app data records (outer AEAD encrypted). */
static int ss_send_fake_new_session_tickets(int fd, shitstorm_state_t *st) {
    for (int t = 0; t < 2; t++) {
        /* Real ticket sizes: 200-250 bytes per ticket */
        uint16_t ticket_size = 200 + (uint16_t)(st->outer_send_key[t] % 51);
        uint8_t fake_ticket[300];
        moor_crypto_random(fake_ticket, ticket_size);

        /* Encrypt as outer AEAD (same as Finished) */
        uint8_t nonce[12];
        memset(nonce, 0, 12);
        for (int i = 0; i < 8; i++)
            nonce[4 + i] = (uint8_t)(st->outer_send_nonce >> (i * 8));
        if (st->outer_send_nonce == UINT64_MAX) return -1;

        uint8_t ct[316];
        unsigned long long ct_len;
        crypto_aead_chacha20poly1305_ietf_encrypt(
            ct, &ct_len, fake_ticket, ticket_size,
            NULL, 0, NULL, nonce, st->outer_send_key);
        st->outer_send_nonce++;

        uint8_t hdr[TLS_RECORD_HEADER];
        ss_tls_record_header(hdr, TLS_APPLICATION_DATA, (uint16_t)ct_len);
        if (ss_send_all(fd, hdr, TLS_RECORD_HEADER) != 0) return -1;
        if (ss_send_all(fd, ct, (size_t)ct_len) != 0) return -1;
    }
    return 0;
}

/* Consume fake NewSessionTicket records (client side) */
static int ss_recv_fake_new_session_tickets(int fd, shitstorm_state_t *st) {
    for (int t = 0; t < 2; t++) {
        uint8_t hdr[TLS_RECORD_HEADER];
        if (ss_recv_all(fd, hdr, TLS_RECORD_HEADER) != 0) return -1;
        if (hdr[0] != TLS_APPLICATION_DATA) return -1;
        uint16_t rec_len = ((uint16_t)hdr[3] << 8) | hdr[4];
        if (rec_len < 16 || rec_len > 400) return -1;

        uint8_t ct[400];
        if (ss_recv_all(fd, ct, rec_len) != 0) return -1;

        /* Decrypt to verify (ensures keys are in sync) */
        uint8_t nonce[12];
        memset(nonce, 0, 12);
        for (int i = 0; i < 8; i++)
            nonce[4 + i] = (uint8_t)(st->outer_recv_nonce >> (i * 8));
        if (st->outer_recv_nonce == UINT64_MAX) return -1;

        uint8_t pt[400];
        unsigned long long pt_len;
        if (crypto_aead_chacha20poly1305_ietf_decrypt(
                pt, &pt_len, NULL, ct, rec_len,
                NULL, 0, nonce, st->outer_recv_key) != 0)
            return -1;
        st->outer_recv_nonce++;
    }
    return 0;
}

static ssize_t shitstorm_send(moor_transport_state_t *state, int fd,
                               const uint8_t *data, size_t len) {
    shitstorm_state_t *st = (shitstorm_state_t *)state;

    /* #5: Key rotation check before encrypting */
    ss_maybe_rekey(st);

    /* Cap payload to fit within TLS record limits.
     * Inner: data + pad(0-15) + pad_len(1) + MAC(16).
     * Outer: obfuscated_len(2) + inner_ct + MAC(16).
     * Total outer plaintext must fit in TLS_MAX_FRAGMENT after outer AEAD. */
    if (len > 4000) len = 4000;

    /* --- INNER LAYER: data + random padding + pad_len byte --- */
    uint8_t inner_pad_len = 0;
    moor_crypto_random(&inner_pad_len, 1);
    inner_pad_len &= 0x0F; /* 0..15 */

    /* First record: pad inner to make total outer ~1400-1500 bytes.
     * outer plaintext = 2 (obfuscated len) + inner_ct_len
     * inner plaintext = data + pad + 1
     * inner_ct = inner_pt + 16
     * outer_pt = 2 + inner_ct
     * outer_ct = outer_pt + 16
     * We want outer_ct ~ 1400-1500 => outer_pt ~ 1384-1484
     * => inner_ct ~ 1382-1482 => inner_pt ~ 1366-1466
     * => data + pad + 1 ~ 1366-1466 => pad ~ 1366-1466 - data - 1 */
    if (st->records_sent == 0) {
        uint32_t rval;
        moor_crypto_random((uint8_t *)&rval, sizeof(rval));
        size_t target_inner_pt = 1366 + (rval % 101); /* 1366-1466 */
        size_t base = len + 1; /* data + pad_len_byte */
        if (base < target_inner_pt) {
            size_t needed_pad = target_inner_pt - base;
            if (needed_pad > 255) needed_pad = 255; /* uint8 pad_len */
            inner_pad_len = (uint8_t)needed_pad;
        }
    }

    /* #1 HTTP/2 framing: wrap data in an h2 DATA frame header (9 bytes).
     * First send: also prepend connection preface + SETTINGS frame.
     * This makes post-handshake content match h2 wire format for DPI. */
    size_t h2_overhead = 9; /* DATA frame header */
    size_t h2_prefix_len = 0;
    uint8_t h2_prefix[64]; /* preface(24) + SETTINGS frame header(9) */
    if (!st->h2_sent_preface) {
        /* HTTP/2 connection preface + empty SETTINGS frame */
        memcpy(h2_prefix, H2_PREFACE, H2_PREFACE_LEN);
        h2_prefix_len = H2_PREFACE_LEN;
        ss_h2_frame_header(h2_prefix + h2_prefix_len, 0, 0x04, 0x00, 0); /* SETTINGS, empty */
        h2_prefix_len += 9;
        st->h2_sent_preface = 1;
    }

    /* Build inner plaintext: [h2_prefix] + [h2 DATA frame header] + [data] + [pad] + [pad_len] */
    size_t inner_pt_len = h2_prefix_len + h2_overhead + len + inner_pad_len + 1;
    uint8_t *inner_pt = malloc(inner_pt_len);
    if (!inner_pt) return -1;

    size_t off = 0;
    if (h2_prefix_len > 0) {
        memcpy(inner_pt, h2_prefix, h2_prefix_len);
        off += h2_prefix_len;
    }
    /* h2 DATA frame: type=0x00, flags=0x00, stream_id=1 */
    ss_h2_frame_header(inner_pt + off, (uint32_t)len, 0x00, 0x00, st->h2_stream_id);
    off += 9;
    memcpy(inner_pt + off, data, len);
    off += len;
    if (inner_pad_len > 0)
        moor_crypto_random(inner_pt + off, inner_pad_len);
    off += inner_pad_len;
    inner_pt[off] = inner_pad_len;
    off++;

    /* Actual inner pt length may differ from estimate due to h2 prefix */
    inner_pt_len = off;

    /* INNER AEAD encrypt */
    if (st->inner_send_nonce == UINT64_MAX) { free(inner_pt); return -1; }

    size_t inner_ct_alloc = inner_pt_len + 16;
    uint8_t *inner_ct = malloc(inner_ct_alloc);
    if (!inner_ct) { free(inner_pt); return -1; }

    uint8_t inner_nonce[12];
    memset(inner_nonce, 0, 12);
    for (int i = 0; i < 8; i++)
        inner_nonce[4 + i] = (uint8_t)(st->inner_send_nonce >> (i * 8));

    unsigned long long inner_ct_len;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        inner_ct, &inner_ct_len,
        inner_pt, inner_pt_len,
        NULL, 0, NULL, inner_nonce, st->inner_send_key);
    free(inner_pt);
    st->inner_send_nonce++;

    /* --- Build outer plaintext: [obfuscated_len:2] + [inner_ct] --- */
    if (inner_ct_len > UINT16_MAX) { free(inner_ct); return -1; }
    size_t outer_pt_len = 2 + (size_t)inner_ct_len;
    uint8_t *outer_pt = malloc(outer_pt_len);
    if (!outer_pt) { free(inner_ct); return -1; }

    /* Obfuscate inner ciphertext length with ChaCha20 keystream */
    uint16_t wire_inner_len = (uint16_t)inner_ct_len;
    outer_pt[0] = (uint8_t)(wire_inner_len >> 8);
    outer_pt[1] = (uint8_t)(wire_inner_len);
    ss_xor_header(outer_pt, st->header_send_key, st->inner_send_nonce - 1);
    memcpy(outer_pt + 2, inner_ct, (size_t)inner_ct_len);
    free(inner_ct);

    /* --- OUTER AEAD encrypt --- */
    if (st->outer_send_nonce == UINT64_MAX) { free(outer_pt); return -1; }

    size_t outer_ct_alloc = outer_pt_len + 16;
    uint8_t *outer_ct = malloc(outer_ct_alloc);
    if (!outer_ct) { free(outer_pt); return -1; }

    uint8_t outer_nonce[12];
    memset(outer_nonce, 0, 12);
    for (int i = 0; i < 8; i++)
        outer_nonce[4 + i] = (uint8_t)(st->outer_send_nonce >> (i * 8));

    unsigned long long outer_ct_len;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        outer_ct, &outer_ct_len,
        outer_pt, outer_pt_len,
        NULL, 0, NULL, outer_nonce, st->outer_send_key);
    free(outer_pt);
    st->outer_send_nonce++;

    /* --- Wrap in TLS Application Data record --- */
    if (outer_ct_len > TLS_MAX_FRAGMENT) { free(outer_ct); return -1; }
    uint8_t hdr[TLS_RECORD_HEADER];
    ss_tls_record_header(hdr, TLS_APPLICATION_DATA, (uint16_t)outer_ct_len);

    if (ss_send_all(fd, hdr, TLS_RECORD_HEADER) != 0) { free(outer_ct); return -1; }
    if (ss_send_all(fd, outer_ct, (size_t)outer_ct_len) != 0) { free(outer_ct); return -1; }
    free(outer_ct);

    st->records_sent++;
    return (ssize_t)len;
}

static ssize_t shitstorm_recv(moor_transport_state_t *state, int fd,
                               uint8_t *buf, size_t len) {
    shitstorm_state_t *st = (shitstorm_state_t *)state;

    /* Return buffered data first */
    if (st->recv_len > 0) {
        size_t copy = (st->recv_len < len) ? st->recv_len : len;
        memcpy(buf, st->recv_buf, copy);
        if (copy < st->recv_len)
            memmove(st->recv_buf, st->recv_buf + copy, st->recv_len - copy);
        st->recv_len -= copy;
        return (ssize_t)copy;
    }

    /* #5: Receiver-side key rotation (before decrypt, mirrors sender) */
    ss_maybe_rekey_recv(st);

    /* --- Read TLS Application Data record --- */
    uint8_t hdr[TLS_RECORD_HEADER];
    if (ss_recv_all(fd, hdr, TLS_RECORD_HEADER) != 0) return -1;
    if (hdr[0] != TLS_APPLICATION_DATA) return -1;
    uint16_t record_len = ((uint16_t)hdr[3] << 8) | hdr[4];
    /* Minimum: 2 (obfuscated len) + 1 (min inner ct) + 16 (inner MAC) + 16 (outer MAC) = 35 */
    if (record_len < 35 || record_len > TLS_MAX_FRAGMENT + 16) return -1;

    uint8_t *record = malloc(record_len);
    if (!record) return -1;
    if (ss_recv_all(fd, record, record_len) != 0) { free(record); return -1; }

    /* --- OUTER AEAD decrypt --- */
    if (st->outer_recv_nonce == UINT64_MAX) { free(record); return -1; }

    uint8_t outer_nonce[12];
    memset(outer_nonce, 0, 12);
    for (int i = 0; i < 8; i++)
        outer_nonce[4 + i] = (uint8_t)(st->outer_recv_nonce >> (i * 8));

    size_t outer_pt_max = record_len;
    uint8_t *outer_pt = malloc(outer_pt_max);
    if (!outer_pt) { free(record); return -1; }

    unsigned long long outer_pt_len;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            outer_pt, &outer_pt_len, NULL,
            record, record_len, NULL, 0,
            outer_nonce, st->outer_recv_key) != 0) {
        LOG_WARN("shitstorm: outer AEAD decryption failed");
        free(record);
        free(outer_pt);
        return -1;
    }
    free(record);
    st->outer_recv_nonce++;

    /* outer_pt = [obfuscated_len:2] + [inner_ct] */
    if (outer_pt_len < 2 + 16 + 1) { free(outer_pt); return -1; } /* too short */

    /* De-obfuscate inner ciphertext length */
    uint8_t len_bytes[2];
    memcpy(len_bytes, outer_pt, 2);
    ss_xor_header(len_bytes, st->header_recv_key, st->inner_recv_nonce);
    uint16_t inner_ct_len = ((uint16_t)len_bytes[0] << 8) | len_bytes[1];

    if ((size_t)inner_ct_len + 2 > (size_t)outer_pt_len) {
        free(outer_pt);
        return -1;
    }

    /* --- INNER AEAD decrypt --- */
    if (st->inner_recv_nonce == UINT64_MAX) { free(outer_pt); return -1; }

    uint8_t inner_nonce[12];
    memset(inner_nonce, 0, 12);
    for (int i = 0; i < 8; i++)
        inner_nonce[4 + i] = (uint8_t)(st->inner_recv_nonce >> (i * 8));

    size_t inner_pt_max = inner_ct_len;
    uint8_t *inner_pt = malloc(inner_pt_max > 0 ? inner_pt_max : 1);
    if (!inner_pt) { free(outer_pt); return -1; }

    unsigned long long inner_pt_len;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            inner_pt, &inner_pt_len, NULL,
            outer_pt + 2, inner_ct_len, NULL, 0,
            inner_nonce, st->inner_recv_key) != 0) {
        LOG_WARN("shitstorm: inner AEAD decryption failed");
        free(outer_pt);
        free(inner_pt);
        return -1;
    }
    free(outer_pt);
    st->inner_recv_nonce++;
    st->records_received++;

    /* Strip padding: last byte is pad_len */
    if (inner_pt_len < 1) { free(inner_pt); return -1; }
    uint8_t pad = inner_pt[inner_pt_len - 1];
    if ((size_t)pad + 1 > (size_t)inner_pt_len) { free(inner_pt); return -1; }
    size_t data_len = (size_t)inner_pt_len - pad - 1;

    /* #1 HTTP/2 frame stripping: skip h2 preface + SETTINGS + DATA frame headers.
     * The sender wraps data in h2 frames.  We need to find the actual data
     * inside the h2 DATA frame(s).  Strategy: scan for h2 frame headers and
     * extract DATA frame payloads, skipping SETTINGS/WINDOW_UPDATE/etc. */
    uint8_t *payload_start = inner_pt;
    size_t payload_len = data_len;
    {
        size_t scan = 0;
        /* Skip HTTP/2 connection preface if present */
        if (data_len >= H2_PREFACE_LEN &&
            memcmp(inner_pt, H2_PREFACE, H2_PREFACE_LEN) == 0)
            scan = H2_PREFACE_LEN;

        /* Walk h2 frames, extract DATA frame payloads */
        uint8_t *extracted = malloc(data_len);
        size_t extracted_len = 0;
        if (extracted) {
            while (scan + 9 <= data_len) {
                uint32_t frame_len = ((uint32_t)inner_pt[scan] << 16) |
                                     ((uint32_t)inner_pt[scan + 1] << 8) |
                                     inner_pt[scan + 2];
                uint8_t frame_type = inner_pt[scan + 3];
                scan += 9; /* skip frame header */
                if (scan + frame_len > data_len) break;
                if (frame_type == 0x00) { /* DATA frame */
                    memcpy(extracted + extracted_len, inner_pt + scan, frame_len);
                    extracted_len += frame_len;
                }
                /* Skip non-DATA frames (SETTINGS=0x04, WINDOW_UPDATE=0x08, etc.) */
                scan += frame_len;
            }
            if (extracted_len > 0) {
                payload_start = extracted;
                payload_len = extracted_len;
            } else {
                /* No h2 frames found -- treat as raw data (backwards compat) */
                free(extracted);
                extracted = NULL;
            }
        }

        /* Reject if data exceeds recv_buf capacity (#R1-A3) */
        if (payload_len > sizeof(st->recv_buf)) {
            if (extracted) free(extracted);
            free(inner_pt);
            return -1;
        }

        size_t copy = (payload_len < len) ? payload_len : len;
        memcpy(buf, payload_start, copy);

        /* Buffer excess data */
        if (payload_len > copy) {
            size_t excess = payload_len - copy;
            if (excess <= sizeof(st->recv_buf) - st->recv_len) {
                memcpy(st->recv_buf + st->recv_len, payload_start + copy, excess);
                st->recv_len += excess;
            }
        }

        if (extracted) free(extracted);
        sodium_memzero(inner_pt, inner_pt_max > 0 ? inner_pt_max : 1);
        free(inner_pt);
        return (ssize_t)copy;
    }
}

static int shitstorm_has_pending(moor_transport_state_t *state) {
    shitstorm_state_t *st = (shitstorm_state_t *)state;
    return st->recv_len > 0;
}

static void shitstorm_free(moor_transport_state_t *state) {
    if (!state) return;
    shitstorm_state_t *st = (shitstorm_state_t *)state;
    sodium_memzero(st, sizeof(*st));
    free(st);
}

/* ================================================================
 * Transport descriptor
 * ================================================================ */
const moor_transport_t moor_shitstorm_transport = {
    .name                 = "shitstorm",
    .client_handshake     = shitstorm_client_handshake,
    .server_handshake     = shitstorm_server_handshake,
    .transport_send       = shitstorm_send,
    .transport_recv       = shitstorm_recv,
    .transport_has_pending = shitstorm_has_pending,
    .transport_free       = shitstorm_free,
};
