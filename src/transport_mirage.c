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

/* Generate random domain-like string for SNI (M2: expanded to 64 high-traffic domains) */
static void generate_random_sni(char *out, size_t out_len) {
    static const char *domains[] = {
        "www.google.com", "www.youtube.com", "www.facebook.com", "www.amazon.com",
        "www.wikipedia.org", "www.twitter.com", "www.instagram.com", "www.linkedin.com",
        "www.reddit.com", "www.netflix.com", "www.microsoft.com", "www.apple.com",
        "www.bing.com", "www.yahoo.com", "www.whatsapp.com", "www.tiktok.com",
        "cdn.cloudflare.com", "cdn.cloudfront.net", "ajax.googleapis.com", "fonts.gstatic.com",
        "static.akamai.net", "content.googleapis.com", "ssl.gstatic.com", "apis.google.com",
        "maps.googleapis.com", "play.google.com", "clients.google.com", "lh3.googleusercontent.com",
        "update.googleapis.com", "storage.googleapis.com", "translate.googleapis.com", "fonts.googleapis.com",
        "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com", "stackpath.bootstrapcdn.com",
        "code.jquery.com", "maxcdn.bootstrapcdn.com", "use.fontawesome.com", "cdn.shopify.com",
        "api.github.com", "raw.githubusercontent.com", "objects.githubusercontent.com", "camo.githubusercontent.com",
        "gateway.discord.gg", "cdn.discordapp.com", "media.discordapp.net", "images-na.ssl-images-amazon.com",
        "m.media-amazon.com", "fls-na.amazon.com", "completion.amazon.com", "s3.amazonaws.com",
        "ec2.amazonaws.com", "sqs.amazonaws.com", "dynamodb.amazonaws.com", "lambda.amazonaws.com",
        "graph.facebook.com", "static.xx.fbcdn.net", "scontent.xx.fbcdn.net", "connect.facebook.net",
        "platform.twitter.com", "abs.twimg.com", "pbs.twimg.com", "api.twitter.com",
    };
    uint32_t idx;
    moor_crypto_random((uint8_t *)&idx, 4);
    snprintf(out, out_len, "%s", domains[idx % (sizeof(domains) / sizeof(domains[0]))]);
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
        if (ext_type == 0x0033 && ext_len >= 38 && pos + 38 <= ext_end) {
            /* key_share: shares_len(2) + group(2) + key_len(2) + key(32) */
            uint16_t key_len = ((uint16_t)body[pos + 4] << 8) | body[pos + 5];
            if (key_len == 32) {
                memcpy(pk_out, body + pos + 6, 32);
                return 0;
            }
        }
        pos += ext_len;
    }
    return -1;
}

/* Derive transport send/recv keys from x25519 DH shared secret + transcript.
 * H1: Binds handshake transcript into key derivation to prevent MitM.
 * is_initiator: 1 for client, 0 for server (determines key direction). */
static int mirage_derive_keys(mirage_state_t *st,
                                 const uint8_t our_sk[32],
                                 const uint8_t their_pk[32],
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

    /* H1: Build hkdf_input = shared(32) || BLAKE2b(transcript)(32) */
    uint8_t transcript_hash[32];
    crypto_generichash_blake2b(transcript_hash, 32,
                                transcript, transcript_len, NULL, 0);
    uint8_t hkdf_input[64];
    memcpy(hkdf_input, shared, 32);
    memcpy(hkdf_input + 32, transcript_hash, 32);
    sodium_memzero(shared, 32);

    /* HKDF-BLAKE2b: derive 64 bytes of key material */
    uint8_t km[64];
    static const uint8_t label[] = "moor-tls-camo-keys";
    crypto_generichash_blake2b(km, 64, hkdf_input, 64, label, sizeof(label) - 1);
    sodium_memzero(hkdf_input, 64);
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
 * Build a TLS 1.3 ClientHello message with a real x25519 key share.
 * The eph_sk_out receives the ephemeral secret key for DH.
 */
static int build_client_hello(uint8_t *buf, size_t buf_len, const char *sni,
                               size_t *out_len, uint8_t eph_sk_out[32]) {
    if (buf_len < 512) return -1;

    size_t sni_len = strlen(sni);
    if (sni_len > 253) sni_len = 253;

    /* ClientHello handshake body — Fix #179: 384 overflows with max SNI (253) */
    uint8_t body[512];
    size_t pos = 0;

    /* client_version = TLS 1.2 (TLS 1.3 uses supported_versions ext) */
    body[pos++] = 0x03;
    body[pos++] = 0x03;

    /* random (32 bytes) */
    moor_crypto_random(body + pos, 32);
    pos += 32;

    /* session_id (32 bytes, random) */
    body[pos++] = 32;  /* length */
    moor_crypto_random(body + pos, 32);
    pos += 32;

    /* cipher_suites */
    body[pos++] = 0x00;
    body[pos++] = 0x06;  /* 6 bytes = 3 suites */
    body[pos++] = (uint8_t)(TLS_AES_128_GCM_SHA256 >> 8);
    body[pos++] = (uint8_t)(TLS_AES_128_GCM_SHA256);
    body[pos++] = (uint8_t)(TLS_AES_256_GCM_SHA384 >> 8);
    body[pos++] = (uint8_t)(TLS_AES_256_GCM_SHA384);
    body[pos++] = (uint8_t)(TLS_CHACHA20_POLY1305_SHA256 >> 8);
    body[pos++] = (uint8_t)(TLS_CHACHA20_POLY1305_SHA256);

    /* compression_methods */
    body[pos++] = 0x01;  /* 1 method */
    body[pos++] = 0x00;  /* null compression */

    /* Extensions */
    size_t ext_start = pos;
    pos += 2;  /* placeholder for extensions length */

    /* SNI extension (type 0x0000) */
    body[pos++] = 0x00; body[pos++] = 0x00;  /* ext type */
    uint16_t sni_ext_len = (uint16_t)(sni_len + 5);
    body[pos++] = (uint8_t)(sni_ext_len >> 8);
    body[pos++] = (uint8_t)(sni_ext_len);
    uint16_t sni_list_len = (uint16_t)(sni_len + 3);
    body[pos++] = (uint8_t)(sni_list_len >> 8);
    body[pos++] = (uint8_t)(sni_list_len);
    body[pos++] = 0x00;  /* host_name type */
    body[pos++] = (uint8_t)(sni_len >> 8);
    body[pos++] = (uint8_t)(sni_len);
    memcpy(body + pos, sni, sni_len);
    pos += sni_len;

    /* supported_versions extension (type 0x002b) -- required for TLS 1.3 */
    body[pos++] = 0x00; body[pos++] = 0x2b;
    body[pos++] = 0x00; body[pos++] = 0x03;  /* ext data len */
    body[pos++] = 0x02;                      /* versions len */
    body[pos++] = 0x03; body[pos++] = 0x04;  /* TLS 1.3 */

    /* key_share extension (type 0x0033) -- real x25519 share for DH */
    body[pos++] = 0x00; body[pos++] = 0x33;
    body[pos++] = 0x00; body[pos++] = 0x26;  /* ext data len = 38 */
    body[pos++] = 0x00; body[pos++] = 0x24;  /* client shares len = 36 */
    body[pos++] = 0x00; body[pos++] = 0x1d;  /* x25519 group */
    body[pos++] = 0x00; body[pos++] = 0x20;  /* key len = 32 */
    /* Generate real x25519 ephemeral keypair */
    uint8_t eph_pk[32];
    crypto_box_keypair(eph_pk, eph_sk_out);
    memcpy(body + pos, eph_pk, 32);
    pos += 32;

    /* Write extensions length */
    uint16_t ext_len = (uint16_t)(pos - ext_start - 2);
    body[ext_start]     = (uint8_t)(ext_len >> 8);
    body[ext_start + 1] = (uint8_t)(ext_len);

    /* Wrap in handshake message: type(1) + length(3) + body */
    size_t hs_len = 1 + 3 + pos;
    uint8_t hs_msg[512];
    hs_msg[0] = TLS_HS_CLIENT_HELLO;
    hs_msg[1] = 0;
    hs_msg[2] = (uint8_t)(pos >> 8);
    hs_msg[3] = (uint8_t)(pos);
    memcpy(hs_msg + 4, body, pos);

    /* Wrap in TLS record */
    tls_record_header(buf, TLS_HANDSHAKE, (uint16_t)(hs_len));
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
    uint8_t ch_buf[512];
    size_t ch_len;
    uint8_t our_eph_sk[32];
    if (build_client_hello(ch_buf, sizeof(ch_buf), sni, &ch_len, our_eph_sk) != 0)
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

    /* H1: Accumulate transcript = CH record || SH record for key binding */
    size_t transcript_len = ch_len + TLS_RECORD_HEADER + sh_len;
    uint8_t *transcript = malloc(transcript_len);
    if (!transcript) {
        sodium_memzero(our_eph_sk, 32);
        return -1;
    }
    memcpy(transcript, ch_buf, ch_len);
    memcpy(transcript + ch_len, sh_buf, TLS_RECORD_HEADER + sh_len);

    /* Handshake complete -- derive transport encryption keys from DH */
    mirage_state_t *st = calloc(1, sizeof(mirage_state_t));
    if (!st) {
        sodium_memzero(our_eph_sk, 32);
        free(transcript);
        return -1;
    }
    if (mirage_derive_keys(st, our_eph_sk, server_eph_pk, 1,
                              transcript, transcript_len) != 0) {
        sodium_memzero(our_eph_sk, 32);
        free(transcript);
        free(st);
        return -1;
    }
    sodium_memzero(our_eph_sk, 32);
    free(transcript);
    st->handshake_done = 1;
    *state_out = (moor_transport_state_t *)st;
    return 0;
}

static int mirage_server_handshake(int fd, const void *params,
                                      moor_transport_state_t **state_out) {
    (void)params;

    /* Receive ClientHello */
    uint8_t ch_hdr[TLS_RECORD_HEADER];
    if (recv_all(fd, ch_hdr, TLS_RECORD_HEADER) != 0) return -1;
    if (ch_hdr[0] != TLS_HANDSHAKE) return -1;
    uint16_t ch_len = ((uint16_t)ch_hdr[3] << 8) | ch_hdr[4];
    if (ch_len > 512 || ch_len < 40) return -1;

    /* Read ClientHello body and extract client's x25519 key */
    uint8_t ch_body[512];
    if (recv_all(fd, ch_body, ch_len) != 0) return -1;
    /* Verify handshake type is ClientHello */
    if (ch_body[0] != TLS_HS_CLIENT_HELLO) return -1;

    uint8_t client_eph_pk[32];
    /* Body starts at offset 4 past handshake type+length */
    if (extract_key_share_from_ch(ch_body + 4, ch_len - 4,
                                   client_eph_pk) != 0) {
        return -1;
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

    /* Derive transport encryption keys from DH */
    mirage_state_t *st = calloc(1, sizeof(mirage_state_t));
    if (!st) {
        sodium_memzero(our_eph_sk, 32);
        free(transcript);
        return -1;
    }
    if (mirage_derive_keys(st, our_eph_sk, client_eph_pk, 0,
                              transcript, transcript_len) != 0) {
        sodium_memzero(our_eph_sk, 32);
        free(transcript);
        free(st);
        return -1;
    }
    sodium_memzero(our_eph_sk, 32);
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

    uint8_t pad_len;
    moor_crypto_random(&pad_len, 1);
    pad_len = (pad_len % 32);  /* 0-31 bytes padding */

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
    return (ssize_t)len;
}

static ssize_t mirage_recv(moor_transport_state_t *state, int fd,
                              uint8_t *buf, size_t len) {
    mirage_state_t *st = (mirage_state_t *)state;

    /* If we have buffered data, return it first */
    if (st->recv_len > 0) {
        size_t copy = (st->recv_len < len) ? st->recv_len : len;
        memcpy(buf, st->recv_buf, copy);
        if (copy < st->recv_len)
            memmove(st->recv_buf, st->recv_buf + copy, st->recv_len - copy);
        st->recv_len -= copy;
        return (ssize_t)copy;
    }

    /* Read TLS record header (use recv_all for reliability) */
    uint8_t hdr[TLS_RECORD_HEADER];
    if (recv_all(fd, hdr, TLS_RECORD_HEADER) != 0) return -1;

    if (hdr[0] != TLS_APPLICATION_DATA) return -1;
    uint16_t record_len = ((uint16_t)hdr[3] << 8) | hdr[4];
    if (record_len < 3 + 16 || record_len > TLS_MAX_FRAGMENT + 16) return -1;

    /* Read full record body (ciphertext + 16-byte MAC) */
    uint8_t record[TLS_MAX_FRAGMENT + 16];
    if (recv_all(fd, record, record_len) != 0) return -1;

    /* Check nonce BEFORE decrypt to prevent keystream reuse (#213) */
    if (st->recv_nonce == UINT64_MAX) return -1;

    /* Decrypt with ChaCha20-Poly1305 AEAD (verifies integrity) */
    uint8_t nonce[12];
    memset(nonce, 0, 12);
    for (int i = 0; i < 8; i++)
        nonce[4 + i] = (uint8_t)(st->recv_nonce >> (i * 8));

    uint8_t decrypted[TLS_MAX_FRAGMENT];
    unsigned long long decrypted_len;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            decrypted, &decrypted_len,
            NULL,
            record, record_len,
            NULL, 0,
            nonce, st->recv_key) != 0) {
        LOG_WARN("TLS camo: AEAD decryption/MAC verification failed");
        return -1;
    }
    st->recv_nonce++;

    /* Extract actual data length from 2-byte prefix (padding discarded) */
    uint16_t data_len = ((uint16_t)decrypted[0] << 8) | decrypted[1];
    if (data_len + 2 > (uint16_t)decrypted_len) return -1; /* corrupt */

    size_t copy = (data_len < len) ? data_len : len;
    memcpy(buf, decrypted + 2, copy);

    /* Buffer excess real data beyond what caller asked for */
    if (data_len > copy) {
        size_t excess = data_len - copy;
        if (excess <= sizeof(st->recv_buf) - st->recv_len) {
            memcpy(st->recv_buf + st->recv_len, decrypted + 2 + copy, excess);
            st->recv_len += excess;
        }
    }

    sodium_memzero(decrypted, sizeof(decrypted));
    return (ssize_t)copy;
}

static int mirage_has_pending(moor_transport_state_t *state) {
    mirage_state_t *st = (mirage_state_t *)state;
    return st->recv_len > 0;
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
