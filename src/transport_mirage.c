/*
 * MOOR -- Mirage Transport
 *
 * Passive DPI evasion: wraps Noise_IK traffic in fake TLS 1.3 records.
 *
 * Client handshake:
 *   Send: ClientHello (TLS 1.3-like, with random session_id, standard ciphers, SNI)
 *   Recv: ServerHello + ChangeCipherSpec
 *
 * Post-handshake:
 *   All data wrapped in TLS Application Data records (content type 23).
 *   Variable-length records break the fixed 532-byte cell pattern.
 *
 * TLS Record format:
 *   ContentType(1) | Version(2) | Length(2) | Fragment(n)
 *   ContentType: 22=Handshake, 23=ApplicationData, 20=ChangeCipherSpec
 *   Version: 0x0303 (TLS 1.2 on wire, TLS 1.3 internally)
 */
#include "moor/moor.h"
#include "moor/transport_mirage.h"
#include <sodium.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#define MSG_NOSIGNAL 0
#else
#include <sys/socket.h>
#endif

/* TLS record types */
#define TLS_CHANGE_CIPHER_SPEC  20
#define TLS_HANDSHAKE           22
#define TLS_APPLICATION_DATA    23

/* TLS handshake types */
#define TLS_HS_CLIENT_HELLO     1
#define TLS_HS_SERVER_HELLO     2

/* TLS version on wire */
#define TLS_VERSION_12          0x0303
#define TLS_VERSION_13          0x0304

/* Max record fragment */
#define TLS_MAX_FRAGMENT        16384
#define TLS_RECORD_HEADER       5

/* Standard TLS 1.3 cipher suite IDs */
#define TLS_AES_128_GCM_SHA256        0x1301
#define TLS_AES_256_GCM_SHA384        0x1302
#define TLS_CHACHA20_POLY1305_SHA256  0x1303

/* Default SNI pool -- rotated per connection to prevent fingerprinting.
 * Bridge operators can override via MirageSNI config (comma-separated).
 * Selected domains: widely used, TLS 1.3, cloud-hosted, hard to block. */
static const char *g_default_sni_pool[] = {
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
#define DEFAULT_SNI_POOL_SIZE (sizeof(g_default_sni_pool) / sizeof(g_default_sni_pool[0]))

/* Operator-configurable SNI pool (set via MirageSNI in moorrc) */
#define MAX_CUSTOM_SNI 64
static char g_custom_sni_buf[MAX_CUSTOM_SNI][256];
static const char *g_custom_sni[MAX_CUSTOM_SNI];
static int g_custom_sni_count = 0;

void moor_mirage_set_sni_pool(const char *csv) {
    g_custom_sni_count = 0;
    if (!csv || !csv[0]) return;
    char buf[4096];
    snprintf(buf, sizeof(buf), "%s", csv);
    char *saveptr = NULL;
    char *tok = strtok_r(buf, ",", &saveptr);
    while (tok && g_custom_sni_count < MAX_CUSTOM_SNI) {
        while (*tok == ' ') tok++;
        if (*tok) {
            snprintf(g_custom_sni_buf[g_custom_sni_count], 256, "%s", tok);
            g_custom_sni[g_custom_sni_count] = g_custom_sni_buf[g_custom_sni_count];
            g_custom_sni_count++;
        }
        tok = strtok_r(NULL, ",", &saveptr);
    }
}

static int sni_pool_size(void) {
    return g_custom_sni_count > 0 ? g_custom_sni_count : (int)DEFAULT_SNI_POOL_SIZE;
}
static const char *sni_pool_get(int idx) {
    if (g_custom_sni_count > 0) return g_custom_sni[idx % g_custom_sni_count];
    return g_default_sni_pool[idx % DEFAULT_SNI_POOL_SIZE];
}

/* Transport state -- includes ChaCha20 stream cipher keys derived from
 * a real x25519 DH during the fake TLS handshake. This makes the TLS
 * camouflage indistinguishable from genuine TLS 1.3 to deep inspection. */
typedef struct {
    uint8_t  recv_buf[TLS_MAX_FRAGMENT + TLS_RECORD_HEADER + 256];
    size_t   recv_len;
    int      handshake_done;
    uint8_t  send_key[32];   /* ChaCha20 key for outgoing records */
    uint8_t  recv_key[32];   /* ChaCha20 key for incoming records */
    uint64_t send_nonce;
    uint64_t recv_nonce;
    uint64_t records_sent;   /* Track sent records for first-record padding */
} mirage_state_t;

/* Helper: send all bytes */
static int send_all(int fd, const uint8_t *data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, (const char *)data + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

/* Helper: recv all bytes */
static int recv_all(int fd, uint8_t *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = recv(fd, (char *)buf + total, len - total, 0);
        if (n <= 0) return -1;
        total += (size_t)n;
    }
    return 0;
}

/* Build a TLS record header */
static void tls_record_header(uint8_t *hdr, uint8_t type, uint16_t length) {
    hdr[0] = type;
    hdr[1] = 0x03;
    hdr[2] = 0x03;  /* TLS 1.2 on wire */
    hdr[3] = (uint8_t)(length >> 8);
    hdr[4] = (uint8_t)(length);
}

/* Select a random SNI from the CDN/cloud pool to prevent fingerprinting.
 * These domains are all CDN/cloud-hosted, TLS 1.3, multi-IP, and unlikely
 * to be individually blocked -- much harder to fingerprint than major sites. */
static void generate_random_sni(char *out, size_t out_len) {
    uint32_t sni_idx;
    moor_crypto_random((uint8_t *)&sni_idx, sizeof(sni_idx));
    snprintf(out, out_len, "%s", sni_pool_get(sni_idx % sni_pool_size()));
}

/* Send fake encrypted handshake records to close the missing-Certificate tell.
 * Real TLS 1.3 sends EncryptedExtensions + Certificate + CertificateVerify +
 * Finished as encrypted records after ServerHello + CCS.  Without these, DPI
 * can detect the absence of a certificate chain.
 *
 * We generate 3-5 records with content_type=0x17 (application data -- TLS 1.3
 * wraps all post-ServerHello content in app-data records) with random content
 * totalling 2000-4000 bytes, mimicking a real certificate chain exchange. */
static int send_fake_encrypted_hs(int fd) {
    uint32_t rval;
    moor_crypto_random((uint8_t *)&rval, sizeof(rval));
    size_t total_target = 2000 + (rval % 2001); /* 2000-4000 bytes total */

    /* Split into 3-5 records of varying size */
    uint32_t nrecs_rnd;
    moor_crypto_random((uint8_t *)&nrecs_rnd, sizeof(nrecs_rnd));
    int num_records = 3 + (int)(nrecs_rnd % 3); /* 3, 4, or 5 records */
    size_t remaining = total_target;

    for (int i = 0; i < num_records; i++) {
        size_t rec_payload;
        if (i == num_records - 1) {
            rec_payload = remaining;
        } else {
            /* Distribute remaining bytes unevenly across remaining records */
            uint32_t frac;
            moor_crypto_random((uint8_t *)&frac, sizeof(frac));
            int left = num_records - i;
            size_t avg = remaining / (size_t)left;
            /* Vary between 60%-140% of average */
            rec_payload = (avg * 60 + (avg * 80 * (frac % 100)) / 100) / 100;
            if (rec_payload > remaining) rec_payload = remaining;
            if (rec_payload < 32) rec_payload = 32;
        }
        if (rec_payload > TLS_MAX_FRAGMENT) rec_payload = TLS_MAX_FRAGMENT;

        uint8_t hdr[TLS_RECORD_HEADER];
        tls_record_header(hdr, TLS_APPLICATION_DATA, (uint16_t)rec_payload);
        if (send_all(fd, hdr, TLS_RECORD_HEADER) != 0) return -1;

        /* Send random content in chunks to avoid huge stack allocation */
        size_t sent = 0;
        while (sent < rec_payload) {
            uint8_t chunk[512];
            size_t csz = rec_payload - sent;
            if (csz > sizeof(chunk)) csz = sizeof(chunk);
            moor_crypto_random(chunk, csz);
            if (send_all(fd, chunk, csz) != 0) return -1;
            sent += csz;
        }
        remaining -= rec_payload;
    }

    /* Send zero-length marker record so client knows fake HS is done */
    uint8_t marker[TLS_RECORD_HEADER];
    tls_record_header(marker, TLS_APPLICATION_DATA, 0);
    if (send_all(fd, marker, TLS_RECORD_HEADER) != 0) return -1;

    return 0;
}

/* Consume fake encrypted handshake records sent by server after CCS.
 * Reads TLS application data records until we see a short marker record
 * (0 bytes payload) or until total bytes consumed reaches 4000+.
 * These are random-filled and simply discarded. */
static int recv_fake_encrypted_hs(int fd) {
    size_t total = 0;
    const size_t max_total = 5000; /* generous upper bound */
    while (total < max_total) {
        uint8_t hdr[TLS_RECORD_HEADER];
        if (recv_all(fd, hdr, TLS_RECORD_HEADER) != 0) return -1;
        if (hdr[0] != TLS_APPLICATION_DATA) return -1;
        uint16_t rec_len = ((uint16_t)hdr[3] << 8) | hdr[4];
        if (rec_len == 0) break; /* marker: end of fake HS records */
        if (rec_len > TLS_MAX_FRAGMENT) return -1;

        /* Read and discard in chunks */
        size_t consumed = 0;
        while (consumed < rec_len) {
            uint8_t discard[512];
            size_t csz = rec_len - consumed;
            if (csz > sizeof(discard)) csz = sizeof(discard);
            if (recv_all(fd, discard, csz) != 0) return -1;
            consumed += csz;
        }
        total += rec_len;
    }
    return 0;
}

/* Extract x25519 public key from a ClientHello body's key_share extension */
static int extract_key_share_from_ch(const uint8_t *body, size_t body_len,
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
        /* R10-INT4: Bounds check extension length against body size */
        if (pos + ext_len > body_len) return -1;
        if (ext_type == 0x0033 && ext_len >= 6) {
            /* key_share: shares_len(2) + [group(2) + key_len(2) + key(N)]...
             * Scan all entries to find the x25519 share (may be after GREASE
             * and ML-KEM entries). */
            uint16_t shares_len = ((uint16_t)body[pos] << 8) | body[pos + 1];
            size_t sp = pos + 2;
            size_t sp_end = pos + 2 + shares_len;
            if (sp_end > pos + ext_len) sp_end = pos + ext_len;
            LOG_DEBUG("mirage: key_share ext found, shares_len=%u, scanning entries", shares_len);
            while (sp + 4 <= sp_end) {
                uint16_t group = ((uint16_t)body[sp] << 8) | body[sp + 1];
                uint16_t key_len = ((uint16_t)body[sp + 2] << 8) | body[sp + 3];
                LOG_DEBUG("mirage: key_share entry group=0x%04x key_len=%u", group, key_len);
                sp += 4;
                if (sp + key_len > sp_end) break;
                if (group == 0x001d && key_len == 32) {
                    memcpy(pk_out, body + sp, 32);
                    return 0;
                }
                sp += key_len;
            }
        }
        pos += ext_len;
    }
    return -1;
}

/* Derive transport send/recv keys from x25519 DH shared secret + transcript.
 * H1: Binds handshake transcript into key derivation to prevent MitM.
 * static_dh: optional 32-byte static-ephemeral DH result for MITM resistance (#6).
 * is_initiator: 1 for client, 0 for server (determines key direction). */
static int mirage_derive_keys(mirage_state_t *st,
                                 const uint8_t our_sk[32],
                                 const uint8_t their_pk[32],
                                 const uint8_t *static_dh,
                                 int is_initiator,
                                 const uint8_t *transcript,
                                 size_t transcript_len) {
    /* M3: Reject low-order points before DH */
    uint8_t test_scalar[32], test_out[32];
    moor_crypto_random(test_scalar, 32);
    if (crypto_scalarmult(test_out, test_scalar, their_pk) != 0 ||
        sodium_is_zero(test_out, 32)) {
        LOG_WARN("TLS camo: low-order point rejected");
        sodium_memzero(test_scalar, 32);
        sodium_memzero(test_out, 32);
        return -1;
    }
    sodium_memzero(test_scalar, 32);
    sodium_memzero(test_out, 32);

    uint8_t shared[32];
    if (moor_crypto_dh(shared, our_sk, their_pk) != 0)
        return -1;

    /* H1: Build hkdf_input = shared(32) [|| static_dh(32)] || BLAKE2b(transcript)(32)
     * When static_dh is present, MITM cannot derive keys without the server's
     * identity secret key (#6). */
    uint8_t transcript_hash[32];
    crypto_generichash_blake2b(transcript_hash, 32,
                                transcript, transcript_len, NULL, 0);
    uint8_t hkdf_input[96]; /* max: shared(32) + static_dh(32) + hash(32) */
    size_t hkdf_len = 0;
    memcpy(hkdf_input + hkdf_len, shared, 32); hkdf_len += 32;
    sodium_memzero(shared, 32);
    if (static_dh) {
        memcpy(hkdf_input + hkdf_len, static_dh, 32); hkdf_len += 32;
    }
    memcpy(hkdf_input + hkdf_len, transcript_hash, 32); hkdf_len += 32;

    /* HKDF-BLAKE2b: derive 64 bytes of key material */
    uint8_t km[64];
    static const uint8_t label[] = "moor-tls-camo-keys";
    crypto_generichash_blake2b(km, 64, hkdf_input, hkdf_len, label, sizeof(label) - 1);
    sodium_memzero(hkdf_input, sizeof(hkdf_input));
    sodium_memzero(transcript_hash, 32);

    if (is_initiator) {
        memcpy(st->send_key, km, 32);
        memcpy(st->recv_key, km + 32, 32);
    } else {
        memcpy(st->recv_key, km, 32);
        memcpy(st->send_key, km + 32, 32);
    }
    st->send_nonce = 0;
    st->recv_nonce = 0;
    sodium_memzero(km, 64);
    return 0;
}

/* Extract x25519 public key from ServerHello body's key_share extension */
static int extract_key_share_from_sh(const uint8_t *body, size_t body_len,
                                      uint8_t pk_out[32]) {
    /* ServerHello: version(2) + random(32) + sid_len(1) + sid(var) +
     * cipher(2) + comp(1) + ext_len(2) + extensions */
    size_t pos = 2 + 32;
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
        /* R10-INT4: Bounds check extension length against body size */
        if (pos + ext_len > body_len) return -1;
        if (ext_type == 0x0033 && ext_len >= 36 && pos + 36 <= ext_end) {
            /* ServerHello key_share: group(2) + key_len(2) + key(32) */
            uint16_t key_len = ((uint16_t)body[pos + 2] << 8) | body[pos + 3];
            if (key_len == 32) {
                memcpy(pk_out, body + pos + 4, 32);
                return 0;
            }
        }
        pos += ext_len;
    }
    return -1;
}

/*
 * Build a TLS 1.3 ClientHello matching Chrome 131+ fingerprint.
 * Full cipher suite list, all Chrome extensions, GREASE, ML-KEM key share.
 * The eph_sk_out receives the ephemeral secret key for DH.
 */
static void mirage_put16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v; }

static uint16_t mirage_grease(void) {
    uint8_t r; moor_crypto_random(&r, 1);
    r = (r & 0xF0) | 0x0A; /* 0x?a?a pattern */
    return ((uint16_t)r << 8) | r;
}

static int build_client_hello(uint8_t *buf, size_t buf_len, const char *sni,
                               size_t *out_len, uint8_t eph_sk_out[32],
                               const uint8_t node_id[32]) {
    if (buf_len < 2048) return -1;

    size_t sni_len = strlen(sni);
    if (sni_len > 253) sni_len = 253;

    uint8_t body[2048];
    size_t pos = 0;

    /* GREASE values for this connection */
    uint16_t grease_cs = mirage_grease();
    uint16_t grease_group = mirage_grease();
    uint16_t grease_ext1 = mirage_grease();
    uint16_t grease_ver = mirage_grease();

    /* client_version = TLS 1.2 on wire (TLS 1.3 via supported_versions) */
    body[pos++] = 0x03; body[pos++] = 0x03;

    /* client_random (32 bytes) */
    moor_crypto_random(body + pos, 32);
    uint8_t *client_random = body + pos;
    pos += 32;

    /* session_id = HMAC(node_id, client_random) for probe resistance */
    body[pos++] = 32;
    if (node_id && !sodium_is_zero(node_id, 32))
        moor_crypto_hash_keyed(body + pos, client_random, 32, node_id);
    else
        moor_crypto_random(body + pos, 32);
    pos += 32;

    /* cipher_suites: 1 GREASE + 15 Chrome suites = 32 bytes */
    mirage_put16(body + pos, 32); pos += 2;
    static const uint16_t chrome_cs[] = {
        0x1301, 0x1302, 0x1303,         /* TLS 1.3 */
        0xc02b, 0xc02f, 0xc02c, 0xc030, /* ECDHE GCM */
        0xcca9, 0xcca8,                  /* ECDHE ChaCha20 */
        0xc013, 0xc014,                  /* ECDHE CBC */
        0x009c, 0x009d, 0x002f, 0x0035,  /* RSA */
    };
    mirage_put16(body + pos, grease_cs); pos += 2;
    for (int i = 0; i < 15; i++) { mirage_put16(body + pos, chrome_cs[i]); pos += 2; }

    /* compression_methods */
    body[pos++] = 0x01; body[pos++] = 0x00;

    /* ---- Extensions ---- */
    size_t ext_start = pos;
    pos += 2; /* placeholder for extensions length */

    /* GREASE extension */
    mirage_put16(body + pos, grease_ext1); pos += 2;
    mirage_put16(body + pos, 1); pos += 2;
    body[pos++] = 0x00;

    /* SNI (0x0000) */
    mirage_put16(body + pos, 0x0000); pos += 2;
    mirage_put16(body + pos, (uint16_t)(sni_len + 5)); pos += 2;
    mirage_put16(body + pos, (uint16_t)(sni_len + 3)); pos += 2;
    body[pos++] = 0x00;
    mirage_put16(body + pos, (uint16_t)sni_len); pos += 2;
    memcpy(body + pos, sni, sni_len); pos += sni_len;

    /* extended_master_secret (0x0017) - empty */
    mirage_put16(body + pos, 0x0017); pos += 2;
    mirage_put16(body + pos, 0); pos += 2;

    /* renegotiation_info (0xff01) */
    mirage_put16(body + pos, 0xff01); pos += 2;
    mirage_put16(body + pos, 1); pos += 2;
    body[pos++] = 0x00;

    /* supported_groups (0x000a): GREASE + X25519MLKEM768 + x25519 + P-256 + P-384 */
    mirage_put16(body + pos, 0x000a); pos += 2;
    mirage_put16(body + pos, 10); pos += 2; /* data len */
    mirage_put16(body + pos, 8); pos += 2;  /* list len */
    mirage_put16(body + pos, grease_group); pos += 2;
    mirage_put16(body + pos, 0x11ec); pos += 2; /* X25519MLKEM768 */
    mirage_put16(body + pos, 0x001d); pos += 2; /* x25519 */
    mirage_put16(body + pos, 0x0017); pos += 2; /* P-256 */

    /* ec_point_formats (0x000b) */
    mirage_put16(body + pos, 0x000b); pos += 2;
    mirage_put16(body + pos, 2); pos += 2;
    body[pos++] = 0x01; body[pos++] = 0x00; /* uncompressed */

    /* session_ticket (0x0023) - empty */
    mirage_put16(body + pos, 0x0023); pos += 2;
    mirage_put16(body + pos, 0); pos += 2;

    /* ALPN (0x0010): h2, http/1.1 */
    mirage_put16(body + pos, 0x0010); pos += 2;
    mirage_put16(body + pos, 14); pos += 2; /* ext data len: 2 + 3 + 9 = 14 */
    mirage_put16(body + pos, 12); pos += 2; /* list len: 3 + 9 = 12 */
    body[pos++] = 2; body[pos++] = 'h'; body[pos++] = '2';
    body[pos++] = 8; memcpy(body + pos, "http/1.1", 8); pos += 8;
    /* NOTE: extension ordering intentionally wrong here -- we don't shuffle
     * because the actual extension ORDER doesn't matter for JA4 (it sorts).
     * What matters is the SET of extensions present. */

    /* status_request (0x0005) - OCSP stapling */
    mirage_put16(body + pos, 0x0005); pos += 2;
    mirage_put16(body + pos, 5); pos += 2;
    body[pos++] = 0x01; /* type: ocsp */
    mirage_put16(body + pos, 0); pos += 2; /* responder_id_list empty */
    mirage_put16(body + pos, 0); pos += 2; /* request_extensions empty */

    /* signature_algorithms (0x000d): 8 Chrome algorithms */
    mirage_put16(body + pos, 0x000d); pos += 2;
    mirage_put16(body + pos, 18); pos += 2; /* ext data len */
    mirage_put16(body + pos, 16); pos += 2; /* list len */
    static const uint16_t chrome_sigalgs[] = {
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601
    };
    for (int i = 0; i < 8; i++) { mirage_put16(body + pos, chrome_sigalgs[i]); pos += 2; }

    /* signed_certificate_timestamp (0x0012) - empty */
    mirage_put16(body + pos, 0x0012); pos += 2;
    mirage_put16(body + pos, 0); pos += 2;

    /* psk_key_exchange_modes (0x002d) */
    mirage_put16(body + pos, 0x002d); pos += 2;
    mirage_put16(body + pos, 2); pos += 2;
    body[pos++] = 0x01; body[pos++] = 0x01; /* psk_dhe_ke */

    /* supported_versions (0x002b): GREASE + TLS 1.3 + TLS 1.2 */
    mirage_put16(body + pos, 0x002b); pos += 2;
    mirage_put16(body + pos, 7); pos += 2;
    body[pos++] = 6; /* versions list len */
    mirage_put16(body + pos, grease_ver); pos += 2;
    mirage_put16(body + pos, 0x0304); pos += 2; /* TLS 1.3 */
    mirage_put16(body + pos, 0x0303); pos += 2; /* TLS 1.2 */

    /* compress_certificate (0x001b): brotli */
    mirage_put16(body + pos, 0x001b); pos += 2;
    mirage_put16(body + pos, 3); pos += 2;
    body[pos++] = 0x02; /* algorithms list len */
    mirage_put16(body + pos, 0x0002); pos += 2; /* brotli */

    /* application_settings / ALPS (0x44cd): Chrome 134+ new code point */
    mirage_put16(body + pos, 0x44cd); pos += 2;
    mirage_put16(body + pos, 5); pos += 2;
    mirage_put16(body + pos, 3); pos += 2; /* protocols list len */
    body[pos++] = 2; body[pos++] = 'h'; body[pos++] = '2';

    /* key_share (0x0033): GREASE + X25519MLKEM768(1216) + x25519(32) */
    {
        uint16_t shares_len = 5 + 1220 + 36; /* GREASE(5) + MLKEM(1220) + x25519(36) */
        mirage_put16(body + pos, 0x0033); pos += 2;
        mirage_put16(body + pos, shares_len + 2); pos += 2; /* ext data len */
        mirage_put16(body + pos, shares_len); pos += 2;     /* shares len */

        /* GREASE share */
        mirage_put16(body + pos, grease_group); pos += 2;
        mirage_put16(body + pos, 1); pos += 2;
        body[pos++] = 0x00;

        /* X25519MLKEM768 (decorative — 1216 bytes random) */
        mirage_put16(body + pos, 0x11ec); pos += 2;
        mirage_put16(body + pos, 1216); pos += 2;
        moor_crypto_random(body + pos, 1216); pos += 1216;

        /* x25519 (real key for DH) */
        mirage_put16(body + pos, 0x001d); pos += 2;
        mirage_put16(body + pos, 32); pos += 2;
        uint8_t eph_pk[32];
        crypto_box_keypair(eph_pk, eph_sk_out);
        memcpy(body + pos, eph_pk, 32); pos += 32;
    }

    /* ECH GREASE (0xfe0d) */
    {
        mirage_put16(body + pos, 0xfe0d); pos += 2;
        uint8_t ech_rand; moor_crypto_random(&ech_rand, 1);
        uint16_t ech_payload_len = 200 + (ech_rand % 56);
        uint16_t ech_ext_len = 1 + 2 + 2 + 1 + 2 + 32 + 2 + ech_payload_len;
        mirage_put16(body + pos, ech_ext_len); pos += 2;
        body[pos++] = 0x00; /* outer */
        mirage_put16(body + pos, 0x0001); pos += 2; /* HKDF-SHA256 */
        mirage_put16(body + pos, 0x0001); pos += 2; /* AES-128-GCM */
        moor_crypto_random(body + pos, 1); pos += 1; /* config_id */
        mirage_put16(body + pos, 32); pos += 2;
        moor_crypto_random(body + pos, 32); pos += 32;
        mirage_put16(body + pos, ech_payload_len); pos += 2;
        moor_crypto_random(body + pos, ech_payload_len); pos += ech_payload_len;
    }

    /* Write extensions length */
    uint16_t ext_len = (uint16_t)(pos - ext_start - 2);
    body[ext_start]     = (uint8_t)(ext_len >> 8);
    body[ext_start + 1] = (uint8_t)(ext_len);

    /* Wrap in handshake message: type(1) + length(3) + body */
    uint8_t hs_msg[2048];
    hs_msg[0] = TLS_HS_CLIENT_HELLO;
    hs_msg[1] = (uint8_t)(pos >> 16);
    hs_msg[2] = (uint8_t)(pos >> 8);
    hs_msg[3] = (uint8_t)(pos);
    memcpy(hs_msg + 4, body, pos);

    /* Wrap in TLS record */
    tls_record_header(buf, TLS_HANDSHAKE, (uint16_t)(4 + pos));
    memcpy(buf + TLS_RECORD_HEADER, hs_msg, 4 + pos);
    *out_len = TLS_RECORD_HEADER + 4 + pos;
    return 0;
}

/*
 * Build a ServerHello + ChangeCipherSpec response with real x25519 key share.
 * The eph_sk_out receives the ephemeral secret key for DH.
 */
static int build_server_hello(uint8_t *buf, size_t buf_len, size_t *out_len,
                               uint8_t eph_sk_out[32],
                               const uint8_t client_session_id[32]) {
    if (buf_len < 300) return -1;

    /* ServerHello body */
    uint8_t body[160];
    size_t pos = 0;

    body[pos++] = 0x03; body[pos++] = 0x03;  /* version */
    moor_crypto_random(body + pos, 32);        /* random */
    pos += 32;

    /* session_id echo (must match ClientHello for real TLS 1.3) */
    body[pos++] = 32;
    memcpy(body + pos, client_session_id, 32);
    pos += 32;

    /* cipher_suite (TLS_CHACHA20_POLY1305_SHA256) */
    body[pos++] = (uint8_t)(TLS_CHACHA20_POLY1305_SHA256 >> 8);
    body[pos++] = (uint8_t)(TLS_CHACHA20_POLY1305_SHA256);

    /* compression = null */
    body[pos++] = 0x00;

    /* Extensions: supported_versions + key_share */
    uint16_t ext_len = 6 + 40; /* supported_versions(6) + key_share(40) */
    body[pos++] = (uint8_t)(ext_len >> 8);
    body[pos++] = (uint8_t)(ext_len);
    body[pos++] = 0x00; body[pos++] = 0x2b;  /* supported_versions */
    body[pos++] = 0x00; body[pos++] = 0x02;
    body[pos++] = 0x03; body[pos++] = 0x04;  /* TLS 1.3 */

    /* key_share extension (type 0x0033) -- real x25519 share */
    body[pos++] = 0x00; body[pos++] = 0x33;
    body[pos++] = 0x00; body[pos++] = 0x24;  /* ext data len = 36 */
    body[pos++] = 0x00; body[pos++] = 0x1d;  /* x25519 group */
    body[pos++] = 0x00; body[pos++] = 0x20;  /* key len = 32 */
    uint8_t eph_pk[32];
    crypto_box_keypair(eph_pk, eph_sk_out);
    memcpy(body + pos, eph_pk, 32);
    pos += 32;

    /* Handshake wrapper */
    uint8_t hs[4 + 160];
    hs[0] = TLS_HS_SERVER_HELLO;
    hs[1] = 0;
    hs[2] = (uint8_t)(pos >> 8);
    hs[3] = (uint8_t)(pos);
    memcpy(hs + 4, body, pos);

    /* TLS record: ServerHello */
    size_t total = 0;
    tls_record_header(buf, TLS_HANDSHAKE, (uint16_t)(4 + pos));
    memcpy(buf + TLS_RECORD_HEADER, hs, 4 + pos);
    total = TLS_RECORD_HEADER + 4 + pos;

    /* TLS record: ChangeCipherSpec */
    tls_record_header(buf + total, TLS_CHANGE_CIPHER_SPEC, 1);
    buf[total + TLS_RECORD_HEADER] = 0x01;
    total += TLS_RECORD_HEADER + 1;

    *out_len = total;
    return 0;
}

/* ---- Transport callbacks ---- */

static int mirage_client_handshake(int fd, const void *params,
                                      moor_transport_state_t **state_out) {
    const moor_mirage_client_params_t *p =
        (const moor_mirage_client_params_t *)params;

    char sni[256];
    if (p && p->sni[0])
        snprintf(sni, sizeof(sni), "%s", p->sni);
    else
        generate_random_sni(sni, sizeof(sni));

    /* Send ClientHello with real x25519 ephemeral key */
    uint8_t ch_buf[2048];
    size_t ch_len;
    uint8_t our_eph_sk[32];
    if (build_client_hello(ch_buf, sizeof(ch_buf), sni, &ch_len, our_eph_sk,
                           p ? p->node_id : NULL) != 0)
        return -1;
    if (send_all(fd, ch_buf, ch_len) != 0) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }

    /* Receive ServerHello + CCS */
    uint8_t sh_buf[512];
    if (recv_all(fd, sh_buf, TLS_RECORD_HEADER) != 0) {
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
    if (recv_all(fd, sh_buf + TLS_RECORD_HEADER, sh_len) != 0) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }

    /* Verify handshake type is ServerHello */
    if (sh_buf[TLS_RECORD_HEADER] != TLS_HS_SERVER_HELLO) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }

    /* Extract server's x25519 public key from ServerHello body
     * (body starts at offset 4 past the handshake type+length) */
    uint8_t server_eph_pk[32];
    if (extract_key_share_from_sh(sh_buf + TLS_RECORD_HEADER + 4,
                                   sh_len - 4, server_eph_pk) != 0) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }

    /* Read CCS record */
    uint8_t ccs_buf[8];
    if (recv_all(fd, ccs_buf, TLS_RECORD_HEADER + 1) != 0) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }
    if (ccs_buf[0] != TLS_CHANGE_CIPHER_SPEC) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }

    /* Consume fake encrypted handshake records (EncryptedExtensions,
     * Certificate, CertificateVerify, Finished) sent by server.
     * These are random-filled and discarded; they exist to make the
     * handshake indistinguishable from real TLS 1.3. */
    if (recv_fake_encrypted_hs(fd) != 0) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }

    /* H1: Accumulate transcript = CH record || SH record for key binding */
    size_t transcript_len = ch_len + TLS_RECORD_HEADER + sh_len;
    uint8_t *transcript = malloc(transcript_len);
    if (!transcript) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }
    memcpy(transcript, ch_buf, ch_len);
    memcpy(transcript + ch_len, sh_buf, TLS_RECORD_HEADER + sh_len);

    /* Compute static-ephemeral DH for MITM resistance (#6):
     * DH(our_eph_sk, curve25519(node_id)) binds server's identity key
     * into session keys. MITM cannot derive this without identity_sk. */
    uint8_t static_dh[32];
    uint8_t *static_dh_ptr = NULL;
    if (p && !sodium_is_zero(p->node_id, 32)) {
        uint8_t node_curve[32];
        if (crypto_sign_ed25519_pk_to_curve25519(node_curve, p->node_id) == 0) {
            if (crypto_scalarmult(static_dh, our_eph_sk, node_curve) == 0 &&
                !sodium_is_zero(static_dh, 32))
                static_dh_ptr = static_dh;
            sodium_memzero(node_curve, 32);
        }
    }

    /* Handshake complete -- derive transport encryption keys from DH */
    mirage_state_t *st = calloc(1, sizeof(mirage_state_t));
    if (!st) {
        sodium_memzero(our_eph_sk, 32);
        sodium_memzero(static_dh, 32);
        free(transcript);
        return -1;
    }
    if (mirage_derive_keys(st, our_eph_sk, server_eph_pk, static_dh_ptr, 1,
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
    st->handshake_done = 1;
    *state_out = (moor_transport_state_t *)st;
    return 0;
}

static int mirage_server_handshake(int fd, const void *params,
                                      moor_transport_state_t **state_out) {
    const moor_mirage_server_params_t *sp =
        (const moor_mirage_server_params_t *)params;

    /* Receive ClientHello */
    uint8_t ch_hdr[TLS_RECORD_HEADER];
    if (recv_all(fd, ch_hdr, TLS_RECORD_HEADER) != 0) {
        LOG_ERROR("mirage server: recv TLS record header failed");
        return -1;
    }
    if (ch_hdr[0] != TLS_HANDSHAKE) {
        LOG_ERROR("mirage server: not a handshake record (got 0x%02x)", ch_hdr[0]);
        return -1;
    }
    uint16_t ch_len = ((uint16_t)ch_hdr[3] << 8) | ch_hdr[4];
    if (ch_len > 2048 || ch_len < 40) {
        LOG_ERROR("mirage server: bad CH length %u", ch_len);
        return -1;
    }

    /* Read ClientHello body and extract client's x25519 key */
    uint8_t ch_body[2048];
    if (recv_all(fd, ch_body, ch_len) != 0) {
        LOG_ERROR("mirage server: recv CH body failed (len=%u)", ch_len);
        return -1;
    }
    /* Verify handshake type is ClientHello */
    if (ch_body[0] != TLS_HS_CLIENT_HELLO) {
        LOG_ERROR("mirage server: not ClientHello (got 0x%02x)", ch_body[0]);
        return -1;
    }

    /* Active probing defense (#7): verify session_id = HMAC(identity_pk, client_random).
     * Only MOOR clients who know our identity can produce a valid session_id.
     * Reject silently (return -1) to be indistinguishable from a connection timeout. */
    if (sp && !sodium_is_zero(sp->identity_pk, 32)) {
        if (ch_len >= 4 + 2 + 32 + 1 + 32) {
            uint8_t *client_random = ch_body + 4 + 2; /* offset: hs_type(1)+len(3)+ver(2) */
            uint8_t sid_len = ch_body[4 + 34];
            if (sid_len != 32) return -1;
            uint8_t expected_sid[32];
            moor_crypto_hash_keyed(expected_sid, client_random, 32, sp->identity_pk);
            if (sodium_memcmp(expected_sid, ch_body + 4 + 35, 32) != 0) {
                sodium_memzero(expected_sid, 32);
                return -1; /* Not a MOOR client — silent reject */
            }
            sodium_memzero(expected_sid, 32);
        } else {
            return -1; /* CH too short for session_id */
        }
    }

    uint8_t client_eph_pk[32];
    /* Body starts at offset 4 past handshake type+length */
    if (extract_key_share_from_ch(ch_body + 4, ch_len - 4,
                                   client_eph_pk) != 0) {
        LOG_ERROR("mirage server: x25519 key share not found in CH (len=%u)", ch_len);
        return -1;
    }
    LOG_DEBUG("mirage server: CH parsed OK (len=%u), key share extracted", ch_len);

    /* Replay cache: reject replayed ClientHello ephemeral keys (CWE-294).
     * Without this, an attacker can record a valid ClientHello and replay
     * it to confirm the server is a MOOR relay. */
    {
        #define MIRAGE_REPLAY_CACHE_SIZE 256
        #define MIRAGE_REPLAY_TTL_SECS   600
        static struct { uint8_t key[32]; uint64_t timestamp; } replay_cache[MIRAGE_REPLAY_CACHE_SIZE];
        static int replay_idx = 0;
        static pthread_mutex_t replay_mutex = PTHREAD_MUTEX_INITIALIZER;
        pthread_mutex_lock(&replay_mutex);
        uint64_t now = (uint64_t)time(NULL);
        for (int r = 0; r < MIRAGE_REPLAY_CACHE_SIZE; r++) {
            if (now - replay_cache[r].timestamp < MIRAGE_REPLAY_TTL_SECS &&
                sodium_memcmp(replay_cache[r].key, client_eph_pk, 32) == 0) {
                pthread_mutex_unlock(&replay_mutex);
                return -1; /* replay detected */
            }
        }
        memcpy(replay_cache[replay_idx].key, client_eph_pk, 32);
        replay_cache[replay_idx].timestamp = now;
        replay_idx = (replay_idx + 1) % MIRAGE_REPLAY_CACHE_SIZE;
        pthread_mutex_unlock(&replay_mutex);
    }

    /* Extract client session_id for echo (offset: 4 + 2 + 32 + 1 = 39) */
    uint8_t client_session_id[32];
    memset(client_session_id, 0, 32);
    if (ch_len >= 4 + 2 + 32 + 1 + 32) {
        uint8_t sid_len = ch_body[4 + 34];
        if (sid_len == 32)
            memcpy(client_session_id, ch_body + 4 + 35, 32);
    }

    /* Send ServerHello + CCS with real x25519 ephemeral key */
    uint8_t sh_buf[512];
    size_t sh_out_len;
    uint8_t our_eph_sk[32];
    if (build_server_hello(sh_buf, sizeof(sh_buf), &sh_out_len, our_eph_sk,
                           client_session_id) != 0) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }
    if (send_all(fd, sh_buf, sh_out_len) != 0) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }

    /* Send fake encrypted handshake records (EncryptedExtensions, Certificate,
     * CertificateVerify, Finished) to close the missing-Certificate tell.
     * Real TLS 1.3 always has these after ServerHello + CCS. */
    if (send_fake_encrypted_hs(fd) != 0) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }

    /* H1: Accumulate transcript = CH record || SH record for key binding.
     * sh_buf contains SH record + CCS record; extract SH record length
     * from its header to exclude CCS (matching what client receives). */
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

    /* Compute static-ephemeral DH for MITM resistance (#6):
     * DH(curve25519(identity_sk), client_eph_pk) — matches client's
     * DH(client_eph_sk, curve25519(identity_pk)). MITM cannot compute this. */
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

    /* Derive transport encryption keys from DH */
    mirage_state_t *st = calloc(1, sizeof(mirage_state_t));
    if (!st) {
        sodium_memzero(our_eph_sk, 32);
        sodium_memzero(static_dh, 32);
        free(transcript);
        return -1;
    }
    if (mirage_derive_keys(st, our_eph_sk, client_eph_pk, static_dh_ptr, 0,
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
    st->handshake_done = 1;
    *state_out = (moor_transport_state_t *)st;
    return 0;
}

static ssize_t mirage_send(moor_transport_state_t *state, int fd,
                              const uint8_t *data, size_t len) {
    mirage_state_t *st = (mirage_state_t *)state;

    /* Wrap in TLS Application Data record with random padding.
     * Record plaintext format: data_len(2) + data(n) + random_pad(m)
     * so receiver can separate real data from padding. */
    if (len > TLS_MAX_FRAGMENT - 2)
        len = TLS_MAX_FRAGMENT - 2;

    uint16_t pad_len;

    /* Pad first app data record to defeat encapsulated-TLS fingerprint.
     * First record size is a strong classifier (Xue et al. 2023).
     * Pad to 1400-1500 bytes to match common HTTP response sizes. */
    if (st->records_sent == 0) {
        uint32_t rval;
        moor_crypto_random((uint8_t *)&rval, sizeof(rval));
        size_t target = 1400 + (rval % 101); /* 1400-1500 bytes plaintext */
        size_t base = 2 + len;
        if (base < target && target <= TLS_MAX_FRAGMENT)
            pad_len = (uint16_t)(target - base);
        else
            pad_len = 0;
    } else {
        uint8_t rnd;
        moor_crypto_random(&rnd, 1);
        pad_len = (rnd % 32);  /* 0-31 bytes padding */
    }

    uint16_t record_len = (uint16_t)(2 + len + pad_len);
    if (record_len > TLS_MAX_FRAGMENT) {
        record_len = (uint16_t)(2 + len);
        pad_len = 0;
    }

    /* Build plaintext: length prefix + data + padding */
    uint8_t plain[TLS_MAX_FRAGMENT];
    plain[0] = (uint8_t)(len >> 8);
    plain[1] = (uint8_t)(len);
    memcpy(plain + 2, data, len);
    if (pad_len > 0)
        moor_crypto_random(plain + 2 + len, pad_len);

    /* Check nonce BEFORE encrypt to prevent keystream reuse (#213) */
    if (st->send_nonce == UINT64_MAX) return -1;

    /* Encrypt with ChaCha20-Poly1305 AEAD for integrity + confidentiality */
    uint8_t nonce[12];
    memset(nonce, 0, 12);
    for (int i = 0; i < 8; i++)
        nonce[4 + i] = (uint8_t)(st->send_nonce >> (i * 8));

    uint8_t encrypted[TLS_MAX_FRAGMENT + 16]; /* +16 for Poly1305 MAC */
    unsigned long long ciphertext_len;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        encrypted, &ciphertext_len,
        plain, record_len,
        NULL, 0,        /* no additional data */
        NULL, nonce, st->send_key);
    st->send_nonce++;

    uint16_t wire_len = (uint16_t)ciphertext_len;
    uint8_t hdr[TLS_RECORD_HEADER];
    tls_record_header(hdr, TLS_APPLICATION_DATA, wire_len);

    if (send_all(fd, hdr, TLS_RECORD_HEADER) != 0) {
        sodium_memzero(plain, sizeof(plain));
        return -1;
    }
    if (send_all(fd, encrypted, wire_len) != 0) {
        sodium_memzero(plain, sizeof(plain));
        return -1;
    }

    sodium_memzero(plain, sizeof(plain));
    st->records_sent++;
    return (ssize_t)len;
}

static ssize_t mirage_recv(moor_transport_state_t *state, int fd,
                              uint8_t *buf, size_t len) {
    mirage_state_t *st = (mirage_state_t *)state;

    /* Incremental TLS record assembly — handles both blocking (handshake)
     * and non-blocking (event loop) sockets. recv_buf accumulates raw wire
     * bytes. We loop until we have a complete TLS record, then decrypt. */

    /* Read until we have at least a TLS record header */
    while (st->recv_len < TLS_RECORD_HEADER) {
        ssize_t n = recv(fd, (char *)st->recv_buf + st->recv_len,
                         sizeof(st->recv_buf) - st->recv_len, 0);
        if (n > 0) { st->recv_len += (size_t)n; continue; }
        if (n == 0) return 0; /* EOF */
        /* EAGAIN on non-blocking socket — no complete record yet */
        if (errno == EAGAIN || errno == EWOULDBLOCK) return -1;
        return -1; /* real error */
    }

    /* Parse TLS record header */
    if (st->recv_buf[0] != TLS_APPLICATION_DATA) {
        LOG_WARN("mirage recv: unexpected record type 0x%02x", st->recv_buf[0]);
        return -1;
    }
    uint16_t record_len = ((uint16_t)st->recv_buf[3] << 8) | st->recv_buf[4];
    if (record_len < 3 + 16 || record_len > TLS_MAX_FRAGMENT + 16) return -1;

    size_t total_needed = TLS_RECORD_HEADER + record_len;

    /* Read until we have the full record */
    while (st->recv_len < total_needed) {
        ssize_t n = recv(fd, (char *)st->recv_buf + st->recv_len,
                         sizeof(st->recv_buf) - st->recv_len, 0);
        if (n > 0) { st->recv_len += (size_t)n; continue; }
        if (n == 0) return 0;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return -1;
        return -1;
    }

    /* Full TLS record available — decrypt */
    if (st->recv_nonce == UINT64_MAX) return -1;

    uint8_t nonce[12];
    memset(nonce, 0, 12);
    for (int i = 0; i < 8; i++)
        nonce[4 + i] = (uint8_t)(st->recv_nonce >> (i * 8));

    uint8_t decrypted[TLS_MAX_FRAGMENT];
    unsigned long long decrypted_len;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            decrypted, &decrypted_len,
            NULL,
            st->recv_buf + TLS_RECORD_HEADER, record_len,
            NULL, 0,
            nonce, st->recv_key) != 0) {
        LOG_WARN("mirage recv: AEAD decrypt failed (nonce=%llu)",
                 (unsigned long long)st->recv_nonce);
        return -1;
    }
    st->recv_nonce++;

    /* Consume the TLS record from the buffer */
    if (total_needed < st->recv_len)
        memmove(st->recv_buf, st->recv_buf + total_needed,
                st->recv_len - total_needed);
    st->recv_len -= total_needed;

    /* Extract actual data from 2-byte length prefix (discard padding) */
    if (decrypted_len < 2) return -1;
    uint16_t data_len = ((uint16_t)decrypted[0] << 8) | decrypted[1];
    if (data_len + 2 > (uint16_t)decrypted_len) return -1;

    size_t copy = (data_len < len) ? data_len : len;
    memcpy(buf, decrypted + 2, copy);
    sodium_memzero(decrypted, sizeof(decrypted));
    return (ssize_t)copy;
}

static int mirage_has_pending(moor_transport_state_t *state) {
    mirage_state_t *st = (mirage_state_t *)state;
    if (st->recv_len < TLS_RECORD_HEADER) return 0;
    uint16_t record_len = ((uint16_t)st->recv_buf[3] << 8) | st->recv_buf[4];
    return st->recv_len >= (size_t)(TLS_RECORD_HEADER + record_len);
}

static void mirage_free(moor_transport_state_t *state) {
    if (state) {
        mirage_state_t *st = (mirage_state_t *)state;
        sodium_memzero(st, sizeof(*st));
        free(state);
    }
}

const moor_transport_t moor_mirage_transport = {
    .name                 = "mirage",
    .client_handshake     = mirage_client_handshake,
    .server_handshake     = mirage_server_handshake,
    .transport_send       = mirage_send,
    .transport_recv       = mirage_recv,
    .transport_has_pending = mirage_has_pending,
    .transport_free       = mirage_free,
};
