#include "moor/moor.h"
#include <sodium.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>

/* Forward declaration — defined below, used by create_descriptor */
static size_t desc_sign_serialize(uint8_t *buf, const moor_node_descriptor_t *desc);

/* ---- Consensus lifecycle ---- */

int moor_consensus_init(moor_consensus_t *cons, uint32_t capacity) {
    memset(cons, 0, sizeof(*cons));
    if (capacity == 0) capacity = 256;  /* reasonable default */
    cons->relays = calloc(capacity, sizeof(moor_node_descriptor_t));
    if (!cons->relays) return -1;
    cons->relay_capacity = capacity;
    return 0;
}

void moor_consensus_cleanup(moor_consensus_t *cons) {
    if (cons->relays) {
        free(cons->relays);
        cons->relays = NULL;
    }
    cons->relay_capacity = 0;
    cons->num_relays = 0;
}

int moor_consensus_copy(moor_consensus_t *dst, const moor_consensus_t *src) {
    /* Free old relay array if present */
    if (dst->relays) free(dst->relays);

    /* Copy fixed fields */
    dst->valid_after = src->valid_after;
    dst->fresh_until = src->fresh_until;
    dst->valid_until = src->valid_until;
    dst->num_relays = src->num_relays;
    dst->num_da_sigs = src->num_da_sigs;
    memcpy(dst->da_sigs, src->da_sigs, sizeof(dst->da_sigs));
    memcpy(dst->srv_current, src->srv_current, 32);
    memcpy(dst->srv_previous, src->srv_previous, 32);

    /* Allocate and copy relay array */
    uint32_t cap = src->num_relays > 0 ? src->num_relays : 1;
    dst->relays = calloc(cap, sizeof(moor_node_descriptor_t));
    if (!dst->relays) {
        dst->num_relays = 0;
        dst->relay_capacity = 0;
        return -1;
    }
    dst->relay_capacity = cap;
    if (src->num_relays > 0 && src->relays)
        memcpy(dst->relays, src->relays,
               src->num_relays * sizeof(moor_node_descriptor_t));
    return 0;
}

int moor_microdesc_consensus_init(moor_microdesc_consensus_t *mc, uint32_t capacity) {
    memset(mc, 0, sizeof(*mc));
    if (capacity == 0) capacity = 256;
    mc->relays = calloc(capacity, sizeof(moor_microdesc_t));
    if (!mc->relays) return -1;
    mc->relay_capacity = capacity;
    return 0;
}

void moor_microdesc_consensus_cleanup(moor_microdesc_consensus_t *mc) {
    if (mc->relays) {
        free(mc->relays);
        mc->relays = NULL;
    }
    mc->relay_capacity = 0;
    mc->num_relays = 0;
}

int moor_microdesc_consensus_copy(moor_microdesc_consensus_t *dst,
                                   const moor_microdesc_consensus_t *src) {
    if (dst->relays) free(dst->relays);

    dst->valid_after = src->valid_after;
    dst->fresh_until = src->fresh_until;
    dst->valid_until = src->valid_until;
    dst->num_relays = src->num_relays;
    dst->num_da_sigs = src->num_da_sigs;
    memcpy(dst->da_sigs, src->da_sigs, sizeof(dst->da_sigs));

    uint32_t cap = src->num_relays > 0 ? src->num_relays : 1;
    dst->relays = calloc(cap, sizeof(moor_microdesc_t));
    if (!dst->relays) return -1;
    dst->relay_capacity = cap;
    if (src->num_relays > 0 && src->relays)
        memcpy(dst->relays, src->relays,
               src->num_relays * sizeof(moor_microdesc_t));
    return 0;
}

int moor_node_create_descriptor(moor_node_descriptor_t *desc,
                                const uint8_t identity_pk[32],
                                const uint8_t identity_sk[64],
                                const uint8_t onion_pk[32],
                                const char *address, uint16_t or_port,
                                uint16_t dir_port, uint32_t flags,
                                uint64_t bandwidth) {
    memset(desc, 0, sizeof(*desc));
    memcpy(desc->identity_pk, identity_pk, 32);
    memcpy(desc->onion_pk, onion_pk, 32);
    if (address)
        strncpy(desc->address, address, sizeof(desc->address) - 1);
    desc->or_port = or_port;
    desc->dir_port = dir_port;
    desc->flags = flags;
    desc->bandwidth = bandwidth;
    desc->published = (uint64_t)time(NULL);

    /* Sign all fields including V3/V4 via shared serializer (#207) */
    uint8_t *buf = malloc(2048);
    if (!buf) return -1;
    size_t off = desc_sign_serialize(buf, desc);
    int ret = moor_crypto_sign(desc->signature, buf, off, identity_sk);
    free(buf);
    return ret;
}

/* Compute wire features: auto-set FAMILY/NICKNAME bits to match serialization */
static uint32_t desc_wire_features(const moor_node_descriptor_t *desc) {
    uint32_t f = desc->features;
    int is_v3 = (desc->num_family_members > 0);
    int has_v4 = (desc->nickname[0] != '\0' || desc->onion_key_version > 0);
    if (is_v3 || has_v4) f |= NODE_FEATURE_FAMILY;
    if (has_v4)           f |= NODE_FEATURE_NICKNAME;
    return f;
}

/* Serialize descriptor fields into buffer for signing/verification.
 * Covers all fields including V3/V4 (#207). Returns bytes written. */
static size_t desc_sign_serialize(uint8_t *buf, const moor_node_descriptor_t *desc) {
    size_t off = 0;
    memcpy(buf + off, desc->identity_pk, 32); off += 32;
    memcpy(buf + off, desc->onion_pk, 32); off += 32;
    memcpy(buf + off, desc->address, 64); off += 64;
    buf[off++] = (uint8_t)(desc->or_port >> 8);
    buf[off++] = (uint8_t)(desc->or_port);
    buf[off++] = (uint8_t)(desc->dir_port >> 8);
    buf[off++] = (uint8_t)(desc->dir_port);
    /* Strip DA-assigned flags (Fast/Stable) — relay never signed those (#208) */
    uint32_t signed_flags = desc->flags & ~NODE_FLAGS_DA_ASSIGNED;
    buf[off++] = (uint8_t)(signed_flags >> 24);
    buf[off++] = (uint8_t)(signed_flags >> 16);
    buf[off++] = (uint8_t)(signed_flags >> 8);
    buf[off++] = (uint8_t)(signed_flags);
    for (int i = 7; i >= 0; i--) buf[off++] = (uint8_t)(desc->bandwidth >> (i * 8));
    for (int i = 7; i >= 0; i--) buf[off++] = (uint8_t)(desc->published >> (i * 8));
    memcpy(buf + off, desc->kem_pk, 1184); off += 1184;
    buf[off++] = (uint8_t)(desc->features >> 24);
    buf[off++] = (uint8_t)(desc->features >> 16);
    buf[off++] = (uint8_t)(desc->features >> 8);
    buf[off++] = (uint8_t)(desc->features);
    /* V3/V4 fields — must be signed to prevent forgery (#207).
     * family_id is excluded: it's DA-computed (not relay-declared). */
    uint8_t nfm = desc->num_family_members;
    if (nfm > 8) nfm = 8;
    buf[off++] = nfm;
    for (int i = 0; i < nfm; i++) {
        memcpy(buf + off, desc->family_members[i], 32); off += 32;
    }
    memcpy(buf + off, desc->nickname, 32); off += 32;
    memcpy(buf + off, desc->address6, 64); off += 64;
    memcpy(buf + off, desc->prev_onion_pk, 32); off += 32;
    for (int i = 3; i >= 0; i--) buf[off++] = (uint8_t)(desc->onion_key_version >> (i * 8));
    for (int i = 7; i >= 0; i--) buf[off++] = (uint8_t)(desc->onion_key_published >> (i * 8));
    return off;
}

int moor_node_sign_descriptor(moor_node_descriptor_t *desc,
                              const uint8_t identity_sk[64]) {
    /* Ensure features match what serialization will produce */
    desc->features = desc_wire_features(desc);

    uint8_t *buf = malloc(2048);
    if (!buf) return -1;
    size_t off = desc_sign_serialize(buf, desc);

    int ret = moor_crypto_sign(desc->signature, buf, off, identity_sk);
    free(buf);
    return ret;
}

int moor_node_verify_descriptor(const moor_node_descriptor_t *desc) {
    uint8_t *buf = malloc(2048);
    if (!buf) return -1;
    size_t off = desc_sign_serialize(buf, desc);

    int ret = moor_crypto_sign_verify(desc->signature, buf, off, desc->identity_pk);
    free(buf);
    return ret;
}

/*
 * Serialize only relay-signed (DA-invariant) fields for consensus body hashing.
 * This is desc_sign_serialize + published timestamp + relay signature, but
 * excluding all DA-local fields: flags (Fast/Stable/BadExit), verified_bandwidth,
 * country_code, as_number, family_id.
 *
 * All DAs with the same relay set produce identical output → identical body hash
 * → cross-DA vote signatures verify successfully.
 */
size_t moor_node_descriptor_signable_serialize(uint8_t *buf,
                                                const moor_node_descriptor_t *desc) {
    return desc_sign_serialize(buf, desc);
}

/*
 * Wire format for descriptor V1:
 *   identity_pk(32) + onion_pk(32) + address(64) + or_port(2) + dir_port(2)
 *   + flags(4) + bandwidth(8) + published(8) + signature(64)
 *   Total: 216 bytes
 *
 * Wire format V2 (when features != 0):
 *   V1 fields (216) + features(4) + kem_pk(1184) + verified_bw(8) +
 *   country_code(2) + as_number(4)
 *   Total: 1418 bytes
 *
 * Wire format V3 (when num_family_members > 0):
 *   V2 fields (1418) + num_family(1) + members(N*32) + family_id(32)
 *   Max: 1418 + 1 + 8*32 + 32 = 1707 bytes
 *
 * Wire format V4 (nickname + IPv6 + key rotation, appended after V3 or V2):
 *   nickname(32) + address6(64) + prev_onion_pk(32) + onion_key_version(4)
 *   + onion_key_published(8) = 140 bytes additional
 */
#define DESC_WIRE_SIZE    216
#define DESC_V2_WIRE_SIZE 1418
#define DESC_V3_MAX_WIRE_SIZE 1707
#define DESC_V4_EXTRA     140
#define DESC_V5_EXTRA     128   /* contact_info(128) */

int moor_node_descriptor_serialize(uint8_t *out, size_t out_len,
                                   const moor_node_descriptor_t *desc) {
    int is_v3 = (desc->num_family_members > 0);
    int is_v2 = (desc->features != 0) || is_v3;
    int has_v4 = (desc->nickname[0] != '\0' || desc->onion_key_version > 0);
    int has_v5 = (desc->contact_info[0] != '\0');
    size_t needed = is_v2 ? DESC_V2_WIRE_SIZE : DESC_WIRE_SIZE;
    if (is_v3)
        needed += 1 + (size_t)desc->num_family_members * 32 + 32;
    if (has_v4 || has_v5) {
        /* V4 requires V2+ base */
        if (!is_v2) { is_v2 = 1; needed = DESC_V2_WIRE_SIZE; }
        /* V4 also requires V3 header (family count + family_id) */
        if (!is_v3) needed += 1 + 32; /* num_family(1) + family_id(32) */
        needed += DESC_V4_EXTRA;
        has_v4 = 1; /* V5 implies V4 present */
    }
    if (has_v5)
        needed += DESC_V5_EXTRA;
    if (is_v2)
        needed += 2; /* V6: protocol_version */
    if (out_len < needed) return -1;

    size_t off = 0;
    memcpy(out + off, desc->identity_pk, 32); off += 32;
    memcpy(out + off, desc->onion_pk, 32); off += 32;
    memcpy(out + off, desc->address, 64); off += 64;
    out[off++] = (uint8_t)(desc->or_port >> 8);
    out[off++] = (uint8_t)(desc->or_port);
    out[off++] = (uint8_t)(desc->dir_port >> 8);
    out[off++] = (uint8_t)(desc->dir_port);
    out[off++] = (uint8_t)(desc->flags >> 24);
    out[off++] = (uint8_t)(desc->flags >> 16);
    out[off++] = (uint8_t)(desc->flags >> 8);
    out[off++] = (uint8_t)(desc->flags);
    for (int i = 7; i >= 0; i--) out[off++] = (uint8_t)(desc->bandwidth >> (i * 8));
    for (int i = 7; i >= 0; i--) out[off++] = (uint8_t)(desc->published >> (i * 8));
    memcpy(out + off, desc->signature, 64); off += 64;

    if (is_v2) {
        /* Auto-set feature flags so deserializer can detect V3/V4/V5 */
        uint32_t wire_features = desc->features;
        if (is_v3 || has_v4) wire_features |= NODE_FEATURE_FAMILY;
        if (has_v4)          wire_features |= NODE_FEATURE_NICKNAME;
        if (has_v5)          wire_features |= NODE_FEATURE_CONTACT;
        out[off++] = (uint8_t)(wire_features >> 24);
        out[off++] = (uint8_t)(wire_features >> 16);
        out[off++] = (uint8_t)(wire_features >> 8);
        out[off++] = (uint8_t)(wire_features);
        memcpy(out + off, desc->kem_pk, 1184); off += 1184;
        for (int i = 7; i >= 0; i--) out[off++] = (uint8_t)(desc->verified_bandwidth >> (i * 8));
        out[off++] = (uint8_t)(desc->country_code >> 8);
        out[off++] = (uint8_t)(desc->country_code);
        out[off++] = (uint8_t)(desc->as_number >> 24);
        out[off++] = (uint8_t)(desc->as_number >> 16);
        out[off++] = (uint8_t)(desc->as_number >> 8);
        out[off++] = (uint8_t)(desc->as_number);
    }

    /* V3: family data -- always write if V3 or V4 (V4 needs V3 header present) */
    if (is_v3 || has_v4) {
        uint8_t nfm = desc->num_family_members;
        if (nfm > 8) nfm = 8;
        out[off++] = nfm;
        for (int i = 0; i < nfm; i++) {
            memcpy(out + off, desc->family_members[i], 32);
            off += 32;
        }
        memcpy(out + off, desc->family_id, 32);
        off += 32;
    }

    /* V4: nickname + IPv6 + key rotation */
    if (has_v4) {
        memcpy(out + off, desc->nickname, 32); off += 32;
        memcpy(out + off, desc->address6, 64); off += 64;
        memcpy(out + off, desc->prev_onion_pk, 32); off += 32;
        out[off++] = (uint8_t)(desc->onion_key_version >> 24);
        out[off++] = (uint8_t)(desc->onion_key_version >> 16);
        out[off++] = (uint8_t)(desc->onion_key_version >> 8);
        out[off++] = (uint8_t)(desc->onion_key_version);
        for (int i = 7; i >= 0; i--) out[off++] = (uint8_t)(desc->onion_key_published >> (i * 8));
    }

    /* V5: contact info */
    if (has_v5) {
        memcpy(out + off, desc->contact_info, 128); off += 128;
    }

    /* V6: protocol version (always written if V2+) */
    if (is_v2) {
        out[off++] = (uint8_t)(desc->protocol_version >> 8);
        out[off++] = (uint8_t)(desc->protocol_version);
    }

    return (int)off;
}

int moor_node_descriptor_deserialize(moor_node_descriptor_t *desc,
                                     const uint8_t *data, size_t data_len) {
    if (data_len < DESC_WIRE_SIZE) return -1;
    memset(desc, 0, sizeof(*desc));

    size_t off = 0;
    memcpy(desc->identity_pk, data + off, 32); off += 32;
    memcpy(desc->onion_pk, data + off, 32); off += 32;
    memcpy(desc->address, data + off, 64); off += 64;
    desc->address[63] = '\0'; /* Ensure null-termination from untrusted wire data */
    /* Sanitize: strip control chars < 0x20, space (0x20), and DEL (0x7F)
     * to prevent consensus line injection (CWE-93) (#R1-C1). */
    for (int c = 0; desc->address[c]; c++)
        if ((unsigned char)desc->address[c] < 0x20 ||
            desc->address[c] == 0x20 || desc->address[c] == 0x7F)
            desc->address[c] = '_';
    desc->or_port = ((uint16_t)data[off] << 8) | data[off + 1]; off += 2;
    desc->dir_port = ((uint16_t)data[off] << 8) | data[off + 1]; off += 2;
    desc->flags = ((uint32_t)data[off] << 24) | ((uint32_t)data[off+1] << 16) |
                  ((uint32_t)data[off+2] << 8) | data[off+3]; off += 4;
    desc->bandwidth = 0;
    for (int i = 7; i >= 0; i--) desc->bandwidth |= (uint64_t)data[off++] << (i * 8);
    desc->published = 0;
    for (int i = 7; i >= 0; i--) desc->published |= (uint64_t)data[off++] << (i * 8);
    memcpy(desc->signature, data + off, 64); off += 64;

    /* V2 extension: if there's more data, try to read features */
    if (data_len >= DESC_V2_WIRE_SIZE) {
        desc->features = ((uint32_t)data[off] << 24) | ((uint32_t)data[off+1] << 16) |
                         ((uint32_t)data[off+2] << 8) | data[off+3];
        off += 4;
        memcpy(desc->kem_pk, data + off, 1184); off += 1184;
        desc->verified_bandwidth = 0;
        for (int i = 7; i >= 0; i--) desc->verified_bandwidth |= (uint64_t)data[off++] << (i * 8);
        desc->country_code = ((uint16_t)data[off] << 8) | data[off + 1]; off += 2;
        desc->as_number = ((uint32_t)data[off] << 24) | ((uint32_t)data[off+1] << 16) |
                          ((uint32_t)data[off+2] << 8) | data[off+3]; off += 4;

        /* V3 extension: family data (gated by feature flag, not buffer length) */
        if (desc->features & (NODE_FEATURE_FAMILY | NODE_FEATURE_NICKNAME)) {
            if (off >= data_len) return -1;
            uint8_t wire_family_count = data[off++];
            uint8_t actual_family = (wire_family_count > 8) ? 8 : wire_family_count;
            desc->num_family_members = actual_family;
            if (wire_family_count > 8)
                LOG_WARN("descriptor has num_family_members=%u, capping to 8",
                         wire_family_count);
            for (int i = 0; i < actual_family; i++) {
                if (off + 32 > data_len) return -1;
                memcpy(desc->family_members[i], data + off, 32);
                off += 32;
            }
            /* Skip excess entries beyond our capacity */
            for (int i = actual_family; i < wire_family_count; i++) {
                if (off + 32 > data_len) return -1;
                off += 32;
            }
            if (off + 32 > data_len) return -1;
            memcpy(desc->family_id, data + off, 32);
            off += 32;

            /* V4 extension: nickname + IPv6 + key rotation (always after V3 header) */
            if ((desc->features & NODE_FEATURE_NICKNAME) &&
                off + DESC_V4_EXTRA <= data_len) {
                memcpy(desc->nickname, data + off, 32); off += 32;
                desc->nickname[31] = '\0';
                /* Sanitize: strip control chars, space, and DEL (CWE-93, #R1-C1) */
                for (int c = 0; desc->nickname[c]; c++)
                    if ((unsigned char)desc->nickname[c] < 0x20 ||
                        desc->nickname[c] == 0x20 || desc->nickname[c] == 0x7F)
                        desc->nickname[c] = '_';
                memcpy(desc->address6, data + off, 64); off += 64;
                desc->address6[63] = '\0';
                for (int c = 0; desc->address6[c]; c++)
                    if ((unsigned char)desc->address6[c] < 0x20 ||
                        desc->address6[c] == 0x20 || desc->address6[c] == 0x7F)
                        desc->address6[c] = '_';
                memcpy(desc->prev_onion_pk, data + off, 32); off += 32;
                desc->onion_key_version = ((uint32_t)data[off] << 24) |
                                          ((uint32_t)data[off+1] << 16) |
                                          ((uint32_t)data[off+2] << 8) | data[off+3];
                off += 4;
                desc->onion_key_published = 0;
                for (int i = 7; i >= 0; i--) desc->onion_key_published |= (uint64_t)data[off++] << (i * 8);

                /* V5 extension: contact info (optional, after V4) */
                if ((desc->features & NODE_FEATURE_CONTACT) &&
                    off + DESC_V5_EXTRA <= data_len) {
                    memcpy(desc->contact_info, data + off, 128); off += 128;
                    desc->contact_info[127] = '\0';
                    for (int c = 0; desc->contact_info[c]; c++)
                        if ((unsigned char)desc->contact_info[c] < 0x20 ||
                            desc->contact_info[c] == 0x20 || desc->contact_info[c] == 0x7F)
                            desc->contact_info[c] = '_';
                }
            }
        }

        /* V6 extension: protocol version (2 bytes, after all other fields) */
        if (off + 2 <= data_len) {
            desc->protocol_version = ((uint16_t)data[off] << 8) | data[off + 1];
            off += 2;
        }
    }

    return (int)off;
}

/*
 * Text-based consensus format (Tor-style, MOOR identity):
 *
 *   moor-consensus 1
 *   valid-after YYYY-MM-DD HH:MM:SS
 *   fresh-until YYYY-MM-DD HH:MM:SS
 *   valid-until YYYY-MM-DD HH:MM:SS
 *   known-flags Authority BadExit Exit Fast Guard MiddleOnly Running Stable Valid
 *   shared-rand-current-value <b64(32)>
 *   shared-rand-previous-value <b64(32)>
 *   n <nickname> <b64(identity_pk)> <published> <IP> <ORport> <DirPort>
 *   o <b64(onion_pk)>
 *   k <b64(kem_pk)>
 *   s Flag1 Flag2 ...
 *   w Bandwidth=N Measured=M
 *   g CC ASN
 *   f <b64(family_id)>
 *   directory-footer
 *   directory-signature <b64(da_identity_pk)> <b64(ed25519_sig)>
 *   pq-directory-signature <b64(da_identity_pk)>
 *   <b64(mldsa_pk)>
 *   <b64(mldsa_sig)>
 */

/* Base64 encode into a caller-supplied buffer. Returns output length (excluding NUL). */
static size_t b64enc(char *out, size_t out_len,
                     const uint8_t *bin, size_t bin_len) {
    if (sodium_bin2base64(out, out_len, bin, bin_len,
                          sodium_base64_VARIANT_ORIGINAL) == NULL)
        return 0;
    return strlen(out);
}

/* Base64 decode. Returns bytes decoded or 0 on error. */
static size_t b64dec(uint8_t *out, size_t out_maxlen,
                     const char *b64, size_t b64_len) {
    size_t decoded_len = 0;
    if (sodium_base642bin(out, out_maxlen, b64, b64_len,
                          NULL, &decoded_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0)
        return 0;
    return decoded_len;
}

/* Format a unix timestamp as "YYYY-MM-DD HH:MM:SS" (19 chars + NUL) */
static void fmt_time(char *buf, size_t len, uint64_t ts) {
    time_t t = (time_t)ts;
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    if (len < 20) { buf[0] = '\0'; return; }
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
    snprintf(buf, 20, "%04d-%02d-%02d %02d:%02d:%02d",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);
#pragma GCC diagnostic pop
}

/* Parse "YYYY-MM-DD HH:MM:SS" to unix timestamp. Returns 0 on error. */
static uint64_t parse_time(const char *s) {
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    int yr, mo, dy, hr, mn, sc;
    if (sscanf(s, "%d-%d-%d %d:%d:%d", &yr, &mo, &dy, &hr, &mn, &sc) != 6)
        return 0;
    tm.tm_year = yr - 1900;
    tm.tm_mon = mo - 1;
    tm.tm_mday = dy;
    tm.tm_hour = hr;
    tm.tm_min = mn;
    tm.tm_sec = sc;
    tm.tm_isdst = 0;
#ifdef _WIN32
    return (uint64_t)_mkgmtime(&tm);
#else
    return (uint64_t)timegm(&tm);
#endif
}

/* Append string to buffer, returns chars written */
static int bcat(uint8_t *out, size_t out_len, size_t *off, const char *s) {
    size_t slen = strlen(s);
    if (*off + slen > out_len) return -1;
    memcpy(out + *off, s, slen);
    *off += slen;
    return (int)slen;
}

/* Flag name table (must be alphabetical for deterministic output) */
static const struct { uint32_t bit; const char *name; } flag_table[] = {
    { NODE_FLAG_AUTHORITY, "Authority" },
    { NODE_FLAG_BADEXIT,   "BadExit" },
    { NODE_FLAG_EXIT,      "Exit" },
    { NODE_FLAG_FAST,      "Fast" },
    { NODE_FLAG_GUARD,     "Guard" },
    { NODE_FLAG_HSDIR,     "HSDir" },
    { NODE_FLAG_MIDDLEONLY, "MiddleOnly" },
    { NODE_FLAG_RUNNING,   "Running" },
    { NODE_FLAG_STABLE,    "Stable" },
    { NODE_FLAG_VALID,     "Valid" },
};
#define NUM_FLAGS (sizeof(flag_table) / sizeof(flag_table[0]))

int moor_consensus_serialize(uint8_t *out, size_t out_len,
                             const moor_consensus_t *cons) {
    size_t off = 0;
    char tmp[8192]; /* scratch buffer for line formatting */

    /* ---- Header ---- */
    if (bcat(out, out_len, &off, "moor-consensus 1\n") < 0) return -1;

    char tbuf[32];
    fmt_time(tbuf, sizeof(tbuf), cons->valid_after);
    snprintf(tmp, sizeof(tmp), "valid-after %s\n", tbuf);
    if (bcat(out, out_len, &off, tmp) < 0) return -1;

    fmt_time(tbuf, sizeof(tbuf), cons->fresh_until);
    snprintf(tmp, sizeof(tmp), "fresh-until %s\n", tbuf);
    if (bcat(out, out_len, &off, tmp) < 0) return -1;

    fmt_time(tbuf, sizeof(tbuf), cons->valid_until);
    snprintf(tmp, sizeof(tmp), "valid-until %s\n", tbuf);
    if (bcat(out, out_len, &off, tmp) < 0) return -1;

    if (bcat(out, out_len, &off,
             "known-flags Authority BadExit Exit Fast Guard "
             "MiddleOnly Running Stable Valid\n") < 0) return -1;

    /* Shared random values */
    {
        char srv_b64[sodium_base64_ENCODED_LEN(32, sodium_base64_VARIANT_ORIGINAL)];
        b64enc(srv_b64, sizeof(srv_b64), cons->srv_current, 32);
        snprintf(tmp, sizeof(tmp), "shared-rand-current-value %s\n", srv_b64);
        if (bcat(out, out_len, &off, tmp) < 0) return -1;

        b64enc(srv_b64, sizeof(srv_b64), cons->srv_previous, 32);
        snprintf(tmp, sizeof(tmp), "shared-rand-previous-value %s\n", srv_b64);
        if (bcat(out, out_len, &off, tmp) < 0) return -1;
    }

    /* ---- Relay entries ---- */
    for (uint32_t ri = 0; ri < cons->num_relays; ri++) {
        const moor_node_descriptor_t *d = &cons->relays[ri];

        /* n <nickname> <b64(identity)> <published> <IP> <ORport> <DirPort> */
        char id_b64[sodium_base64_ENCODED_LEN(32, sodium_base64_VARIANT_ORIGINAL)];
        b64enc(id_b64, sizeof(id_b64), d->identity_pk, 32);

        char pub_time[32];
        fmt_time(pub_time, sizeof(pub_time), d->published);

        /* Extract IP from address (strip :port if present) */
        char ip_str[64];
        strncpy(ip_str, d->address, sizeof(ip_str) - 1);
        ip_str[sizeof(ip_str) - 1] = '\0';
        { char *c = strchr(ip_str, ':'); if (c) *c = '\0'; }

        const char *nn = (d->nickname[0] != '\0') ? d->nickname : "Unnamed";
        snprintf(tmp, sizeof(tmp), "n %s %s %s %s %u %u\n",
                 nn, id_b64, pub_time, ip_str, d->or_port, d->dir_port);
        if (bcat(out, out_len, &off, tmp) < 0) return -1;

        /* o <b64(onion_pk)> */
        char onion_b64[sodium_base64_ENCODED_LEN(32, sodium_base64_VARIANT_ORIGINAL)];
        b64enc(onion_b64, sizeof(onion_b64), d->onion_pk, 32);
        snprintf(tmp, sizeof(tmp), "o %s\n", onion_b64);
        if (bcat(out, out_len, &off, tmp) < 0) return -1;

        /* a [IPv6]:port -- only if relay has IPv6 address */
        if (d->address6[0] != '\0') {
            snprintf(tmp, sizeof(tmp), "a %s\n", d->address6);
            if (bcat(out, out_len, &off, tmp) < 0) return -1;
        }

        /* k <b64(kem_pk)> -- only if PQ-capable */
        if (d->features & NODE_FEATURE_PQ) {
            char *kem_b64 = malloc(sodium_base64_ENCODED_LEN(1184, sodium_base64_VARIANT_ORIGINAL));
            if (kem_b64) {
                b64enc(kem_b64,
                       sodium_base64_ENCODED_LEN(1184, sodium_base64_VARIANT_ORIGINAL),
                       d->kem_pk, 1184);
                size_t klen = strlen(kem_b64);
                /* "k " + b64 + "\n" */
                if (off + 2 + klen + 1 <= out_len) {
                    out[off++] = 'k';
                    out[off++] = ' ';
                    memcpy(out + off, kem_b64, klen);
                    off += klen;
                    out[off++] = '\n';
                }
                free(kem_b64);
            }
        }

        /* s Flag1 Flag2 ... (alphabetical) */
        {
            size_t soff = 0;
            tmp[soff++] = 's';
            for (size_t fi = 0; fi < NUM_FLAGS; fi++) {
                if (d->flags & flag_table[fi].bit) {
                    tmp[soff++] = ' ';
                    size_t nlen = strlen(flag_table[fi].name);
                    memcpy(tmp + soff, flag_table[fi].name, nlen);
                    soff += nlen;
                }
            }
            tmp[soff++] = '\n';
            tmp[soff] = '\0';
            if (bcat(out, out_len, &off, tmp) < 0) return -1;
        }

        /* w Bandwidth=N [Measured=M] */
        if (d->verified_bandwidth > 0)
            snprintf(tmp, sizeof(tmp), "w Bandwidth=%llu Measured=%llu\n",
                     (unsigned long long)d->bandwidth,
                     (unsigned long long)d->verified_bandwidth);
        else
            snprintf(tmp, sizeof(tmp), "w Bandwidth=%llu\n",
                     (unsigned long long)d->bandwidth);
        if (bcat(out, out_len, &off, tmp) < 0) return -1;

        /* g CC ASN */
        if (d->country_code != 0) {
            char cc[3];
            moor_geoip_unpack_country(d->country_code, cc);
            snprintf(tmp, sizeof(tmp), "g %s %u\n", cc, d->as_number);
            if (bcat(out, out_len, &off, tmp) < 0) return -1;
        }

        /* f <b64(family_id)> -- only if non-zero */
        {
            static const uint8_t zero32[32] = {0};
            if (memcmp(d->family_id, zero32, 32) != 0) {
                char fid_b64[sodium_base64_ENCODED_LEN(32, sodium_base64_VARIANT_ORIGINAL)];
                b64enc(fid_b64, sizeof(fid_b64), d->family_id, 32);
                snprintf(tmp, sizeof(tmp), "f %s\n", fid_b64);
                if (bcat(out, out_len, &off, tmp) < 0) return -1;
            }
        }

        /* descriptor signature (relay's own Ed25519 sig) */
        {
            char sig_b64[sodium_base64_ENCODED_LEN(64, sodium_base64_VARIANT_ORIGINAL)];
            b64enc(sig_b64, sizeof(sig_b64), d->signature, 64);
            snprintf(tmp, sizeof(tmp), "p %s\n", sig_b64);
            if (bcat(out, out_len, &off, tmp) < 0) return -1;
        }

        /* c <contact_info> -- only if non-empty */
        if (d->contact_info[0] != '\0') {
            snprintf(tmp, sizeof(tmp), "c %s\n", d->contact_info);
            if (bcat(out, out_len, &off, tmp) < 0) return -1;
        }
    }

    /* Bandwidth weights (Tor-aligned: embedded so all clients use identical values) */
    snprintf(tmp, sizeof(tmp),
             "bandwidth-weights Wgg=%d Wgd=%d Wee=%d Wed=%d Wmg=%d Wme=%d Wmm=%d Wmd=%d\n",
             cons->bw_weights[BW_WGG], cons->bw_weights[BW_WGD],
             cons->bw_weights[BW_WEE], cons->bw_weights[BW_WED],
             cons->bw_weights[BW_WMG], cons->bw_weights[BW_WME],
             cons->bw_weights[BW_WMM], cons->bw_weights[BW_WMD]);
    if (bcat(out, out_len, &off, tmp) < 0) return -1;

    /* ---- Footer ---- */
    if (bcat(out, out_len, &off, "directory-footer\n") < 0) return -1;

    for (uint32_t i = 0; i < cons->num_da_sigs && i < MOOR_MAX_DA_AUTHORITIES; i++) {
        char pk_b64[sodium_base64_ENCODED_LEN(32, sodium_base64_VARIANT_ORIGINAL)];
        char sig_b64[sodium_base64_ENCODED_LEN(64, sodium_base64_VARIANT_ORIGINAL)];
        b64enc(pk_b64, sizeof(pk_b64), cons->da_sigs[i].identity_pk, 32);
        b64enc(sig_b64, sizeof(sig_b64), cons->da_sigs[i].signature, 64);
        snprintf(tmp, sizeof(tmp), "directory-signature %s %s\n", pk_b64, sig_b64);
        if (bcat(out, out_len, &off, tmp) < 0) return -1;

        if (cons->da_sigs[i].has_pq) {
            char *pq_pk_b64 = malloc(sodium_base64_ENCODED_LEN(MOOR_MLDSA_PK_LEN, sodium_base64_VARIANT_ORIGINAL));
            char *pq_sig_b64 = malloc(sodium_base64_ENCODED_LEN(MOOR_MLDSA_SIG_LEN, sodium_base64_VARIANT_ORIGINAL));
            if (pq_pk_b64 && pq_sig_b64) {
                b64enc(pq_pk_b64,
                       sodium_base64_ENCODED_LEN(MOOR_MLDSA_PK_LEN, sodium_base64_VARIANT_ORIGINAL),
                       cons->da_sigs[i].pq_pk, MOOR_MLDSA_PK_LEN);
                b64enc(pq_sig_b64,
                       sodium_base64_ENCODED_LEN(MOOR_MLDSA_SIG_LEN, sodium_base64_VARIANT_ORIGINAL),
                       cons->da_sigs[i].pq_signature, MOOR_MLDSA_SIG_LEN);

                snprintf(tmp, sizeof(tmp), "pq-directory-signature %s\n", pk_b64);
                if (bcat(out, out_len, &off, tmp) < 0) { free(pq_pk_b64); free(pq_sig_b64); return -1; }

                /* PQ public key on its own line */
                size_t pklen = strlen(pq_pk_b64);
                if (off + pklen + 1 <= out_len) {
                    memcpy(out + off, pq_pk_b64, pklen);
                    off += pklen;
                    out[off++] = '\n';
                }

                /* PQ signature on its own line */
                size_t siglen = strlen(pq_sig_b64);
                if (off + siglen + 1 <= out_len) {
                    memcpy(out + off, pq_sig_b64, siglen);
                    off += siglen;
                    out[off++] = '\n';
                }
            }
            free(pq_pk_b64);
            free(pq_sig_b64);
        }
    }

    return (int)off;
}

/* Read one line from data buffer. Returns line length (including \n),
 * or 0 if no more data. Copies up to linesz-1 chars into line[]. */
static size_t read_line(const uint8_t *data, size_t data_len, size_t pos,
                        char *line, size_t linesz) {
    if (pos >= data_len) return 0;
    size_t start = pos;
    while (pos < data_len && data[pos] != '\n')
        pos++;
    if (pos < data_len) pos++; /* consume \n */
    size_t len = pos - start;
    size_t copy = (len < linesz - 1) ? len : (linesz - 1);
    memcpy(line, data + start, copy);
    line[copy] = '\0';
    /* Strip trailing newline for easier parsing */
    if (copy > 0 && line[copy - 1] == '\n') line[copy - 1] = '\0';
    if (copy > 1 && line[copy - 2] == '\r') line[copy - 2] = '\0';
    return len;
}

/* Parse flag names from an "s Flag1 Flag2 ..." line into bitmask */
static uint32_t parse_flags(const char *s) {
    uint32_t flags = 0;
    /* Skip "s " prefix */
    if (s[0] == 's' && s[1] == ' ') s += 2;
    else return 0;
    while (*s) {
        while (*s == ' ') s++;
        if (*s == '\0') break;
        const char *end = s;
        while (*end && *end != ' ') end++;
        size_t wlen = (size_t)(end - s);
        for (size_t fi = 0; fi < NUM_FLAGS; fi++) {
            if (strlen(flag_table[fi].name) == wlen &&
                strncmp(s, flag_table[fi].name, wlen) == 0) {
                flags |= flag_table[fi].bit;
                break;
            }
        }
        s = end;
    }
    return flags;
}

/* Ensure relay array has capacity for at least n+1 entries */
static int cons_ensure_cap(moor_consensus_t *cons, uint32_t needed) {
    if (cons->relays && cons->relay_capacity >= needed) return 0;
    if (needed > MOOR_MAX_RELAYS) return -1;  /* check BEFORE doubling loop */
    uint32_t new_cap = cons->relay_capacity ? cons->relay_capacity : 256;
    while (new_cap < needed && new_cap <= MOOR_MAX_RELAYS / 2) new_cap *= 2;
    if (new_cap < needed) new_cap = needed;
    if (new_cap > MOOR_MAX_RELAYS) new_cap = MOOR_MAX_RELAYS;
    moor_node_descriptor_t *grown = realloc(cons->relays,
        (size_t)new_cap * sizeof(moor_node_descriptor_t));
    if (!grown) return -1;
    memset(grown + cons->relay_capacity, 0,
           (new_cap - cons->relay_capacity) * sizeof(moor_node_descriptor_t));
    cons->relays = grown;
    cons->relay_capacity = new_cap;
    return 0;
}

int moor_consensus_deserialize(moor_consensus_t *cons,
                               const uint8_t *data, size_t data_len) {
    if (data_len < 20) return -1;

    /* Check for text format: starts with "moor-consensus" */
    if (data_len < 17 || memcmp(data, "moor-consensus", 14) != 0) {
        LOG_WARN("consensus: unrecognized format");
        return -1;
    }

    /* Initialize */
    cons->num_relays = 0;
    cons->num_da_sigs = 0;
    memset(cons->srv_current, 0, 32);
    memset(cons->srv_previous, 0, 32);
    memset(cons->da_sigs, 0, sizeof(cons->da_sigs));

    char line[8192];
    size_t pos = 0;
    int in_footer = 0;
    int current_relay = -1;  /* index of relay being parsed */

    while (pos < data_len) {
        size_t adv = read_line(data, data_len, pos, line, sizeof(line));
        if (adv == 0) break;
        pos += adv;

        if (line[0] == '\0') continue;

        /* Header fields */
        if (strncmp(line, "moor-consensus ", 15) == 0) {
            continue; /* version line, already validated */
        }
        else if (strncmp(line, "valid-after ", 12) == 0) {
            cons->valid_after = parse_time(line + 12);
        }
        else if (strncmp(line, "fresh-until ", 12) == 0) {
            cons->fresh_until = parse_time(line + 12);
        }
        else if (strncmp(line, "valid-until ", 12) == 0) {
            cons->valid_until = parse_time(line + 12);
        }
        else if (strncmp(line, "known-flags ", 12) == 0) {
            continue; /* informational */
        }
        else if (strncmp(line, "shared-rand-current-value ", 25) == 0) {
            b64dec(cons->srv_current, 32, line + 25, strlen(line + 25));
        }
        else if (strncmp(line, "shared-rand-previous-value ", 27) == 0) {
            b64dec(cons->srv_previous, 32, line + 27, strlen(line + 27));
        }
        /* Relay entry start: "n <nickname> <b64(id)> <time> <IP> <ORport> <DirPort>" */
        else if (line[0] == 'n' && line[1] == ' ' && !in_footer) {
            if (cons_ensure_cap(cons, cons->num_relays + 1) != 0)
                return -1;
            current_relay = (int)cons->num_relays;
            moor_node_descriptor_t *d = &cons->relays[current_relay];
            memset(d, 0, sizeof(*d));
            cons->num_relays++;

            /* Parse: n <nickname> <b64(id)> <YYYY-MM-DD> <HH:MM:SS> <IP> <ORport> <DirPort> */
            char nickname[64], id_b64[64], date_s[16], time_s[16], ip_s[64];
            unsigned int or_port = 0, dir_port = 0;
            if (sscanf(line + 2, "%63s %63s %15s %15s %63s %u %u",
                       nickname, id_b64, date_s, time_s, ip_s,
                       &or_port, &dir_port) >= 7) {
                strncpy(d->nickname, nickname, 31);
                d->nickname[31] = '\0';
                if (strcmp(d->nickname, "Unnamed") == 0) d->nickname[0] = '\0';

                b64dec(d->identity_pk, 32, id_b64, strlen(id_b64));

                char ts_buf[40];
                snprintf(ts_buf, sizeof(ts_buf), "%s %s", date_s, time_s);
                d->published = parse_time(ts_buf);

                memset(d->address, 0, sizeof(d->address));
                memcpy(d->address, ip_s,
                       strlen(ip_s) < sizeof(d->address) - 1 ?
                       strlen(ip_s) : sizeof(d->address) - 1);
                d->or_port = (uint16_t)or_port;
                d->dir_port = (uint16_t)dir_port;
            }
        }
        /* Onion key: "o <b64(onion_pk)>" */
        else if (line[0] == 'o' && line[1] == ' ' && current_relay >= 0 && !in_footer) {
            b64dec(cons->relays[current_relay].onion_pk, 32,
                   line + 2, strlen(line + 2));
        }
        /* IPv6 address: "a [addr]:port" (like Tor's "a" line) */
        else if (line[0] == 'a' && line[1] == ' ' && current_relay >= 0 && !in_footer) {
            memset(cons->relays[current_relay].address6, 0, 64);
            memcpy(cons->relays[current_relay].address6, line + 2,
                   strlen(line + 2) < 63 ? strlen(line + 2) : 63);
        }
        /* KEM key: "k <b64(kem_pk)>" */
        else if (line[0] == 'k' && line[1] == ' ' && current_relay >= 0 && !in_footer) {
            size_t decoded = b64dec(cons->relays[current_relay].kem_pk, 1184,
                                    line + 2, strlen(line + 2));
            if (decoded == 1184)
                cons->relays[current_relay].features |= NODE_FEATURE_PQ;
        }
        /* Flags: "s Flag1 Flag2 ..." */
        else if (line[0] == 's' && line[1] == ' ' && current_relay >= 0 && !in_footer) {
            cons->relays[current_relay].flags = parse_flags(line);
        }
        /* Bandwidth: "w Bandwidth=N [Measured=M]" */
        else if (line[0] == 'w' && line[1] == ' ' && current_relay >= 0 && !in_footer) {
            unsigned long long bw = 0, measured = 0;
            const char *p = strstr(line, "Bandwidth=");
            if (p) bw = strtoull(p + 10, NULL, 10);
            p = strstr(line, "Measured=");
            if (p) measured = strtoull(p + 9, NULL, 10);
            cons->relays[current_relay].bandwidth = (uint64_t)bw;
            cons->relays[current_relay].verified_bandwidth = (uint64_t)measured;
        }
        /* GeoIP: "g CC ASN" */
        else if (line[0] == 'g' && line[1] == ' ' && current_relay >= 0 && !in_footer) {
            char cc[4] = {0};
            unsigned int asn = 0;
            if (sscanf(line + 2, "%2s %u", cc, &asn) >= 1) {
                cons->relays[current_relay].country_code = moor_geoip_pack_country(cc);
                cons->relays[current_relay].as_number = asn;
            }
        }
        /* Family: "f <b64(family_id)>" */
        else if (line[0] == 'f' && line[1] == ' ' && current_relay >= 0 && !in_footer) {
            b64dec(cons->relays[current_relay].family_id, 32,
                   line + 2, strlen(line + 2));
        }
        /* Descriptor signature: "p <b64(relay_sig)>" */
        else if (line[0] == 'p' && line[1] == ' ' && current_relay >= 0 && !in_footer) {
            b64dec(cons->relays[current_relay].signature, 64,
                   line + 2, strlen(line + 2));
        }
        /* Contact info: "c <contact_info>" */
        else if (line[0] == 'c' && line[1] == ' ' && current_relay >= 0 && !in_footer) {
            snprintf(cons->relays[current_relay].contact_info,
                     sizeof(cons->relays[current_relay].contact_info),
                     "%s", line + 2);
        }
        /* Bandwidth weights: "bandwidth-weights Wgg=X Wgd=X Wee=X Wed=X Wmg=X Wme=X Wmm=X Wmd=X" */
        else if (strncmp(line, "bandwidth-weights ", 18) == 0) {
            int wgg = 0, wgd = 0, wee = 0, wed = 0, wmg = 0, wme = 0, wmm = 0, wmd = 0;
            if (sscanf(line + 18,
                       "Wgg=%d Wgd=%d Wee=%d Wed=%d Wmg=%d Wme=%d Wmm=%d Wmd=%d",
                       &wgg, &wgd, &wee, &wed, &wmg, &wme, &wmm, &wmd) == 8) {
                cons->bw_weights[BW_WGG] = (int32_t)wgg;
                cons->bw_weights[BW_WGD] = (int32_t)wgd;
                cons->bw_weights[BW_WEE] = (int32_t)wee;
                cons->bw_weights[BW_WED] = (int32_t)wed;
                cons->bw_weights[BW_WMG] = (int32_t)wmg;
                cons->bw_weights[BW_WME] = (int32_t)wme;
                cons->bw_weights[BW_WMM] = (int32_t)wmm;
                cons->bw_weights[BW_WMD] = (int32_t)wmd;
            }
        }
        /* Footer marker */
        else if (strncmp(line, "directory-footer", 16) == 0) {
            in_footer = 1;
            current_relay = -1;
        }
        /* DA Ed25519 signature: "directory-signature <b64(pk)> <b64(sig)>" */
        else if (strncmp(line, "directory-signature ", 19) == 0 && in_footer) {
            if (cons->num_da_sigs >= MOOR_MAX_DA_AUTHORITIES) continue;
            uint32_t si = cons->num_da_sigs++;

            char pk_b64[64], sig_b64[128];
            if (sscanf(line + 19, "%63s %127s", pk_b64, sig_b64) >= 2) {
                b64dec(cons->da_sigs[si].identity_pk, 32,
                       pk_b64, strlen(pk_b64));
                b64dec(cons->da_sigs[si].signature, 64,
                       sig_b64, strlen(sig_b64));
                cons->da_sigs[si].has_pq = 0;
            }
        }
        /* PQ DA signature: "pq-directory-signature <b64(pk)>" followed by 2 lines */
        else if (strncmp(line, "pq-directory-signature ", 22) == 0 && in_footer) {
            /* Find matching DA sig by identity_pk */
            char pk_b64[64];
            if (sscanf(line + 22, "%63s", pk_b64) < 1) continue;

            uint8_t search_pk[32];
            b64dec(search_pk, 32, pk_b64, strlen(pk_b64));

            int found = -1;
            for (uint32_t si = 0; si < cons->num_da_sigs; si++) {
                if (memcmp(cons->da_sigs[si].identity_pk, search_pk, 32) == 0) {
                    found = (int)si;
                    break;
                }
            }
            if (found < 0) continue;

            /* Next line: ML-DSA public key (base64) */
            char pq_line[8192];
            adv = read_line(data, data_len, pos, pq_line, sizeof(pq_line));
            if (adv == 0) continue;
            pos += adv;
            b64dec(cons->da_sigs[found].pq_pk, MOOR_MLDSA_PK_LEN,
                   pq_line, strlen(pq_line));

            /* Next line: ML-DSA signature (base64) */
            adv = read_line(data, data_len, pos, pq_line, sizeof(pq_line));
            if (adv == 0) continue;
            pos += adv;
            b64dec(cons->da_sigs[found].pq_signature, MOOR_MLDSA_SIG_LEN,
                   pq_line, strlen(pq_line));

            cons->da_sigs[found].has_pq = 1;
        }
    }

    if (cons->valid_after == 0) return -1;
    return (int)pos;
}

int moor_node_same_family(const moor_node_descriptor_t *a,
                          const moor_node_descriptor_t *b) {
    /* Two relays are in the same family if both have non-zero family_id
     * and the IDs are equal */
    static const uint8_t zero[32] = {0};
    if (sodium_memcmp(a->family_id, zero, 32) == 0) return 0;
    if (sodium_memcmp(b->family_id, zero, 32) == 0) return 0;
    return (sodium_memcmp(a->family_id, b->family_id, 32) == 0) ? 1 : 0;
}

const moor_node_descriptor_t *moor_node_select_relay(
    const moor_consensus_t *cons, uint32_t required_flags,
    const uint8_t *exclude_ids, int num_exclude) {
    if (!cons->relays || cons->num_relays == 0) return NULL;

    /* Heap-allocate candidate/weight arrays for >2048 relay support */
    const moor_node_descriptor_t **candidates = malloc(
        cons->num_relays * sizeof(moor_node_descriptor_t *));
    uint64_t *cum_bw = malloc(cons->num_relays * sizeof(uint64_t));
    if (!candidates || !cum_bw) {
        free(candidates); free(cum_bw);
        return NULL;
    }
    int count = 0;

    for (uint32_t i = 0; i < cons->num_relays; i++) {
        const moor_node_descriptor_t *r = &cons->relays[i];

        /* Check required flags */
        if ((r->flags & required_flags) != required_flags)
            continue;

        /* Exclude BADEXIT relays from exit selection */
        if ((required_flags & NODE_FLAG_EXIT) &&
            (r->flags & NODE_FLAG_BADEXIT))
            continue;

        /* Exclude MiddleOnly relays from guard and exit positions */
        if ((required_flags & (NODE_FLAG_GUARD | NODE_FLAG_EXIT)) &&
            (r->flags & NODE_FLAG_MIDDLEONLY))
            continue;

        /* Check exclusion list */
        int excluded = 0;
        if (exclude_ids) {
            for (int j = 0; j < num_exclude; j++) {
                if (sodium_memcmp(r->identity_pk, exclude_ids + j * 32, 32) == 0) {
                    excluded = 1;
                    break;
                }
            }
        }
        if (excluded) continue;

        candidates[count++] = r;
    }

    if (count == 0) { free(candidates); free(cum_bw); return NULL; }

    /* Tor-aligned: use bandwidth weights from consensus document.
     * Every client uses the same Wgg/Wgd/Wee/Wed/Wmg/Wme/Wmm/Wmd values
     * computed by the DA during consensus build.  Scale = BW_WEIGHT_SCALE. */
    int selecting_guard = (required_flags & NODE_FLAG_GUARD) != 0;
    int selecting_exit  = (required_flags & NODE_FLAG_EXIT)  != 0;
    const int32_t *W = cons->bw_weights;
    int32_t S = BW_WEIGHT_SCALE;
    /* If consensus has no weights (old DA), fall back to uniform */
    int have_weights = 0;
    for (int wi = 0; wi < 8; wi++) { if (W[wi] != 0) { have_weights = 1; break; } }

    uint64_t total_bw = 0;
    for (int i = 0; i < count; i++) {
        uint64_t bw = candidates[i]->bandwidth;
        if (bw < 1000) bw = 1000;
        if (bw > 1000000000ULL) bw = 1000000000ULL;

        if (have_weights) {
            int is_g = (candidates[i]->flags & NODE_FLAG_GUARD) != 0;
            int is_e = (candidates[i]->flags & NODE_FLAG_EXIT)  != 0;
            int32_t w;

            if (selecting_guard) {
                if (is_g && is_e) w = W[BW_WGD];
                else              w = W[BW_WGG];
            } else if (selecting_exit) {
                if (is_g && is_e) w = W[BW_WED];
                else              w = W[BW_WEE];
            } else {
                /* Middle position */
                if (is_g && is_e) w = W[BW_WMD];
                else if (is_g)    w = W[BW_WMG];
                else if (is_e)    w = W[BW_WME];
                else              w = W[BW_WMM];
            }
            if (w < 0) w = 0;
            bw = (bw * (uint64_t)w) / (uint64_t)S;
        }

        if (bw == 0) bw = 1;
        total_bw += bw;
        cum_bw[i] = total_bw;
    }

    /* Unbiased random value in [0, total_bw) via rejection sampling */
    if (total_bw == 0) { free(candidates); free(cum_bw); return NULL; }
    uint64_t r;
    uint64_t limit = UINT64_MAX - (UINT64_MAX % total_bw);
    do {
        moor_crypto_random((uint8_t *)&r, sizeof(r));
    } while (r >= limit);
    r %= total_bw;

    /* Binary search for the selected relay */
    int lo = 0, hi = count - 1;
    while (lo < hi) {
        int mid = (lo + hi) / 2;
        if (cum_bw[mid] <= r)
            lo = mid + 1;
        else
            hi = mid;
    }
    const moor_node_descriptor_t *result = candidates[lo];
    free(candidates);
    free(cum_bw);
    return result;
}

const moor_node_descriptor_t *moor_node_select_relay_diverse(
    const moor_consensus_t *cons, uint32_t required_flags,
    const uint8_t *exclude_ids, int num_exclude,
    const moor_node_descriptor_t **selected_descs, int num_selected) {

    /* Try up to 10 times to find a relay in a different country/AS */
    for (int attempt = 0; attempt < 10; attempt++) {
        const moor_node_descriptor_t *candidate =
            moor_node_select_relay(cons, required_flags, exclude_ids, num_exclude);
        if (!candidate) return NULL;

        /* Check diversity against already-selected hops */
        int conflict = 0;
        for (int i = 0; i < num_selected && selected_descs; i++) {
            if (!selected_descs[i]) continue;

            /* Check family */
            if (moor_node_same_family(candidate, selected_descs[i])) {
                conflict = 1;
                break;
            }
            /* Check country */
            if (candidate->country_code != 0 &&
                candidate->country_code == selected_descs[i]->country_code) {
                conflict = 1;
                break;
            }
            /* Check AS */
            if (candidate->as_number != 0 &&
                candidate->as_number == selected_descs[i]->as_number) {
                conflict = 1;
                break;
            }
        }

        if (!conflict)
            return candidate;
    }

    /* Fallback: accept any relay after 10 retries */
    return moor_node_select_relay(cons, required_flags, exclude_ids, num_exclude);
}

/*
 * Microdescriptor wire format: 150 bytes
 *   identity_pk(32) + onion_pk(32) + flags(4) + bandwidth(8) +
 *   features(4) + family_id(32) + country_code(2) + as_number(4) + nickname(32)
 */
#define MICRODESC_WIRE_SIZE 150

int moor_microdesc_serialize(uint8_t *out, size_t out_len,
                             const moor_microdesc_t *md) {
    if (out_len < MICRODESC_WIRE_SIZE) return -1;
    size_t off = 0;
    memcpy(out + off, md->identity_pk, 32); off += 32;
    memcpy(out + off, md->onion_pk, 32); off += 32;
    out[off++] = (uint8_t)(md->flags >> 24);
    out[off++] = (uint8_t)(md->flags >> 16);
    out[off++] = (uint8_t)(md->flags >> 8);
    out[off++] = (uint8_t)(md->flags);
    for (int i = 7; i >= 0; i--) out[off++] = (uint8_t)(md->bandwidth >> (i * 8));
    out[off++] = (uint8_t)(md->features >> 24);
    out[off++] = (uint8_t)(md->features >> 16);
    out[off++] = (uint8_t)(md->features >> 8);
    out[off++] = (uint8_t)(md->features);
    memcpy(out + off, md->family_id, 32); off += 32;
    out[off++] = (uint8_t)(md->country_code >> 8);
    out[off++] = (uint8_t)(md->country_code);
    out[off++] = (uint8_t)(md->as_number >> 24);
    out[off++] = (uint8_t)(md->as_number >> 16);
    out[off++] = (uint8_t)(md->as_number >> 8);
    out[off++] = (uint8_t)(md->as_number);
    memcpy(out + off, md->nickname, 32); off += 32;
    return (int)off;
}

int moor_microdesc_deserialize(moor_microdesc_t *md,
                               const uint8_t *data, size_t data_len) {
    if (data_len < MICRODESC_WIRE_SIZE) return -1;
    memset(md, 0, sizeof(*md));
    size_t off = 0;
    memcpy(md->identity_pk, data + off, 32); off += 32;
    memcpy(md->onion_pk, data + off, 32); off += 32;
    md->flags = ((uint32_t)data[off] << 24) | ((uint32_t)data[off+1] << 16) |
                ((uint32_t)data[off+2] << 8) | data[off+3]; off += 4;
    md->bandwidth = 0;
    for (int i = 7; i >= 0; i--) md->bandwidth |= (uint64_t)data[off++] << (i * 8);
    md->features = ((uint32_t)data[off] << 24) | ((uint32_t)data[off+1] << 16) |
                   ((uint32_t)data[off+2] << 8) | data[off+3]; off += 4;
    memcpy(md->family_id, data + off, 32); off += 32;
    md->country_code = ((uint16_t)data[off] << 8) | data[off + 1]; off += 2;
    md->as_number = ((uint32_t)data[off] << 24) | ((uint32_t)data[off+1] << 16) |
                    ((uint32_t)data[off+2] << 8) | data[off+3]; off += 4;
    memcpy(md->nickname, data + off, 32); off += 32;
    md->nickname[31] = '\0';
    return (int)off;
}

int moor_microdesc_consensus_serialize(uint8_t *out, size_t out_len,
                                       const moor_microdesc_consensus_t *mc) {
    /* Calculate needed size accounting for PQ fields */
    int mc_has_pq = 0;
    for (uint32_t i = 0; i < mc->num_da_sigs && i < MOOR_MAX_DA_AUTHORITIES; i++) {
        if (mc->da_sigs[i].has_pq) { mc_has_pq = 1; break; }
    }
    size_t needed = 28 + (size_t)mc->num_relays * MICRODESC_WIRE_SIZE + 4;
    for (uint32_t i = 0; i < mc->num_da_sigs && i < MOOR_MAX_DA_AUTHORITIES; i++) {
        needed += 96;
        if (mc_has_pq) {
            needed += 1;
            if (mc->da_sigs[i].has_pq)
                needed += (size_t)MOOR_MLDSA_SIG_LEN + MOOR_MLDSA_PK_LEN;
        }
    }
    if (out_len < needed) return -1;

    size_t off = 0;
    for (int i = 7; i >= 0; i--) out[off++] = (uint8_t)(mc->valid_after >> (i * 8));
    for (int i = 7; i >= 0; i--) out[off++] = (uint8_t)(mc->fresh_until >> (i * 8));
    for (int i = 7; i >= 0; i--) out[off++] = (uint8_t)(mc->valid_until >> (i * 8));
    out[off++] = (uint8_t)(mc->num_relays >> 24);
    out[off++] = (uint8_t)(mc->num_relays >> 16);
    out[off++] = (uint8_t)(mc->num_relays >> 8);
    out[off++] = (uint8_t)(mc->num_relays);

    for (uint32_t i = 0; i < mc->num_relays; i++) {
        int n = moor_microdesc_serialize(out + off, out_len - off, &mc->relays[i]);
        if (n < 0) return -1;
        off += n;
    }

    /* Multi-DA signatures with PQ magic header */
    int mc_any_pq = 0;
    for (uint32_t i = 0; i < mc->num_da_sigs && i < MOOR_MAX_DA_AUTHORITIES; i++) {
        if (mc->da_sigs[i].has_pq) { mc_any_pq = 1; break; }
    }

    if (mc_any_pq) {
        out[off++] = 0x50;
        out[off++] = 0x51;
        out[off++] = 0x00;
        out[off++] = (uint8_t)(mc->num_da_sigs);
    } else {
        out[off++] = (uint8_t)(mc->num_da_sigs >> 24);
        out[off++] = (uint8_t)(mc->num_da_sigs >> 16);
        out[off++] = (uint8_t)(mc->num_da_sigs >> 8);
        out[off++] = (uint8_t)(mc->num_da_sigs);
    }

    for (uint32_t i = 0; i < mc->num_da_sigs && i < MOOR_MAX_DA_AUTHORITIES; i++) {
        memcpy(out + off, mc->da_sigs[i].signature, 64); off += 64;
        memcpy(out + off, mc->da_sigs[i].identity_pk, 32); off += 32;
        if (mc_any_pq) {
            out[off++] = mc->da_sigs[i].has_pq;
            if (mc->da_sigs[i].has_pq) {
                memcpy(out + off, mc->da_sigs[i].pq_signature, MOOR_MLDSA_SIG_LEN);
                off += MOOR_MLDSA_SIG_LEN;
                memcpy(out + off, mc->da_sigs[i].pq_pk, MOOR_MLDSA_PK_LEN);
                off += MOOR_MLDSA_PK_LEN;
            }
        }
    }

    return (int)off;
}

int moor_microdesc_consensus_deserialize(moor_microdesc_consensus_t *mc,
                                          const uint8_t *data, size_t data_len) {
    if (data_len < 28) return -1;
    /* Save relays pointer before zeroing (caller may have pre-allocated) */
    moor_microdesc_t *saved_relays = mc->relays;
    uint32_t saved_cap = mc->relay_capacity;
    memset(mc, 0, sizeof(*mc));
    mc->relays = saved_relays;
    mc->relay_capacity = saved_cap;

    size_t off = 0;
    mc->valid_after = 0;
    for (int i = 7; i >= 0; i--) mc->valid_after |= (uint64_t)data[off++] << (i * 8);
    mc->fresh_until = 0;
    for (int i = 7; i >= 0; i--) mc->fresh_until |= (uint64_t)data[off++] << (i * 8);
    mc->valid_until = 0;
    for (int i = 7; i >= 0; i--) mc->valid_until |= (uint64_t)data[off++] << (i * 8);
    mc->num_relays = ((uint32_t)data[off] << 24) | ((uint32_t)data[off+1] << 16) |
                     ((uint32_t)data[off+2] << 8) | data[off+3];
    off += 4;

    if (mc->num_relays > MOOR_MAX_RELAYS) return -1;

    /* Allocate relay array if needed */
    if (!mc->relays || mc->relay_capacity < mc->num_relays) {
        free(mc->relays);
        mc->relays = calloc(mc->num_relays > 0 ? mc->num_relays : 1,
                            sizeof(moor_microdesc_t));
        if (!mc->relays) return -1;
        mc->relay_capacity = mc->num_relays > 0 ? mc->num_relays : 1;
    }

    for (uint32_t i = 0; i < mc->num_relays; i++) {
        int n = moor_microdesc_deserialize(&mc->relays[i], data + off, data_len - off);
        if (n < 0) return -1;
        off += n;
    }

    /* Multi-DA signatures -- detect PQ magic */
    if (off + 4 > data_len) return -1;
    int mc_is_pq = (data[off] == 0x50 && data[off+1] == 0x51 && data[off+2] == 0x00);

    if (mc_is_pq) {
        mc->num_da_sigs = data[off+3];
    } else {
        mc->num_da_sigs = ((uint32_t)data[off] << 24) | ((uint32_t)data[off+1] << 16) |
                          ((uint32_t)data[off+2] << 8) | data[off+3];
    }
    off += 4;

    if (mc->num_da_sigs > MOOR_MAX_DA_AUTHORITIES) return -1;

    for (uint32_t i = 0; i < mc->num_da_sigs; i++) {
        if (off + 96 > data_len) return -1;
        memcpy(mc->da_sigs[i].signature, data + off, 64); off += 64;
        memcpy(mc->da_sigs[i].identity_pk, data + off, 32); off += 32;

        if (mc_is_pq) {
            if (off + 1 > data_len) return -1;
            mc->da_sigs[i].has_pq = data[off++];
            if (mc->da_sigs[i].has_pq) {
                size_t pq_sz = (size_t)MOOR_MLDSA_SIG_LEN + MOOR_MLDSA_PK_LEN;
                if (off + pq_sz > data_len) return -1;
                memcpy(mc->da_sigs[i].pq_signature, data + off, MOOR_MLDSA_SIG_LEN);
                off += MOOR_MLDSA_SIG_LEN;
                memcpy(mc->da_sigs[i].pq_pk, data + off, MOOR_MLDSA_PK_LEN);
                off += MOOR_MLDSA_PK_LEN;
            } else {
                memset(mc->da_sigs[i].pq_signature, 0, MOOR_MLDSA_SIG_LEN);
                memset(mc->da_sigs[i].pq_pk, 0, MOOR_MLDSA_PK_LEN);
            }
        } else {
            mc->da_sigs[i].has_pq = 0;
        }
    }

    return (int)off;
}

void moor_microdesc_to_descriptor(moor_node_descriptor_t *out,
                                  const moor_microdesc_t *md) {
    memset(out, 0, sizeof(*out));
    memcpy(out->identity_pk, md->identity_pk, 32);
    memcpy(out->onion_pk, md->onion_pk, 32);
    /* address is zeroed -- middle relay must resolve from its own consensus */
    out->flags = md->flags;
    out->bandwidth = md->bandwidth;
    out->features = md->features;
    memcpy(out->family_id, md->family_id, 32);
    out->country_code = md->country_code;
    out->as_number = md->as_number;
    memcpy(out->nickname, md->nickname, 32);
}

const moor_node_descriptor_t *moor_node_select_relay_pq(
    const moor_consensus_t *cons, uint32_t required_flags,
    const uint8_t *exclude_ids, int num_exclude) {
    if (!cons->relays || cons->num_relays == 0) return NULL;

    /* Heap-allocate for >2048 relay support */
    const moor_node_descriptor_t **candidates = malloc(
        cons->num_relays * sizeof(moor_node_descriptor_t *));
    uint64_t *cum_bw = malloc(cons->num_relays * sizeof(uint64_t));
    if (!candidates || !cum_bw) {
        free(candidates); free(cum_bw);
        return NULL;
    }
    int count = 0;

    for (uint32_t i = 0; i < cons->num_relays; i++) {
        const moor_node_descriptor_t *r = &cons->relays[i];

        if ((r->flags & required_flags) != required_flags)
            continue;
        if (!(r->features & NODE_FEATURE_PQ))
            continue;

        int excluded = 0;
        if (exclude_ids) {
            for (int j = 0; j < num_exclude; j++) {
                if (sodium_memcmp(r->identity_pk, exclude_ids + j * 32, 32) == 0) {
                    excluded = 1;
                    break;
                }
            }
        }
        if (excluded) continue;

        candidates[count++] = r;
    }

    if (count == 0) { free(candidates); free(cum_bw); return NULL; }

    /* Bandwidth-weighted selection */
    uint64_t total_bw = 0;
    for (int i = 0; i < count; i++) {
        uint64_t bw = candidates[i]->bandwidth;
        if (bw < 1000) bw = 1000;
        if (bw > 1000000000ULL) bw = 1000000000ULL;
        total_bw += bw;
        cum_bw[i] = total_bw;
    }

    if (total_bw == 0) { free(candidates); free(cum_bw); return NULL; }
    uint64_t r;
    uint64_t limit = UINT64_MAX - (UINT64_MAX % total_bw);
    do {
        moor_crypto_random((uint8_t *)&r, sizeof(r));
    } while (r >= limit);
    r %= total_bw;

    int lo = 0, hi = count - 1;
    while (lo < hi) {
        int mid = (lo + hi) / 2;
        if (cum_bw[mid] <= r)
            lo = mid + 1;
        else
            hi = mid;
    }
    const moor_node_descriptor_t *result = candidates[lo];
    free(candidates);
    free(cum_bw);
    return result;
}

size_t moor_consensus_wire_size(const moor_consensus_t *cons) {
    /* Text format: generous upper bound.
     * Header: ~512 bytes
     * Per relay: n(200) + o(50) + k(1600) + s(100) + w(50) + g(20) + f(50) + p(100) ≈ 2200
     * Per DA sig: directory-signature(200) + pq-directory-signature(8192) ≈ 8400
     * Footer: 32 */
    size_t sz = 512;
    sz += (size_t)cons->num_relays * 2200;
    for (uint32_t i = 0; i < cons->num_da_sigs && i < MOOR_MAX_DA_AUTHORITIES; i++) {
        sz += 256; /* directory-signature line */
        if (cons->da_sigs[i].has_pq)
            sz += 8192; /* PQ pk + sig in base64 */
    }
    sz += 64; /* footer + slack */
    return sz;
}

const moor_node_descriptor_t *moor_node_find_by_nickname(
    const moor_consensus_t *cons, const char *name) {
    if (!name || !name[0] || !cons->relays) return NULL;
    for (uint32_t i = 0; i < cons->num_relays; i++) {
        const char *nn = cons->relays[i].nickname;
        if (nn[0] == '\0') continue;
        /* Case-insensitive compare */
        const char *a = name, *b = nn;
        int match = 1;
        while (*a && *b) {
            if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
                match = 0;
                break;
            }
            a++; b++;
        }
        if (match && *a == '\0' && *b == '\0')
            return &cons->relays[i];
    }
    return NULL;
}

/* ---- Consensus compression (zlib) ---- */

#ifdef _WIN32
/* zlib not available in MinGW cross-compile; stubs return -1 */
int moor_consensus_compress(const uint8_t *data, size_t len,
                             uint8_t **out, size_t *out_len) {
    (void)data; (void)len; (void)out; (void)out_len;
    return -1;
}
int moor_consensus_decompress(const uint8_t *data, size_t len,
                               uint8_t **out, size_t *out_len) {
    (void)data; (void)len; (void)out; (void)out_len;
    return -1;
}
int moor_consensus_is_compressed(const uint8_t *data, size_t len) {
    if (!data || len < 4) return 0;
    uint32_t magic = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                     ((uint32_t)data[2] << 8) | data[3];
    return (magic == MOOR_COMPRESS_MAGIC) ? 1 : 0;
}
#else
#include <zlib.h>

int moor_consensus_compress(const uint8_t *data, size_t len,
                             uint8_t **out, size_t *out_len) {
    if (!data || !out || !out_len) return -1;
    /* MZLB header: magic(4) + uncompressed_len(4) + compressed data */
    uLongf comp_bound = compressBound((uLong)len);
    *out = malloc(8 + comp_bound);
    if (!*out) return -1;

    /* Write MZLB header */
    (*out)[0] = (uint8_t)(MOOR_COMPRESS_MAGIC >> 24);
    (*out)[1] = (uint8_t)(MOOR_COMPRESS_MAGIC >> 16);
    (*out)[2] = (uint8_t)(MOOR_COMPRESS_MAGIC >> 8);
    (*out)[3] = (uint8_t)(MOOR_COMPRESS_MAGIC);
    (*out)[4] = (uint8_t)(len >> 24);
    (*out)[5] = (uint8_t)(len >> 16);
    (*out)[6] = (uint8_t)(len >> 8);
    (*out)[7] = (uint8_t)(len);

    uLongf dest_len = comp_bound;
    int rc = compress2((*out) + 8, &dest_len, data, (uLong)len, Z_DEFAULT_COMPRESSION);
    if (rc != Z_OK) {
        free(*out);
        *out = NULL;
        return -1;
    }
    *out_len = 8 + (size_t)dest_len;
    return 0;
}

int moor_consensus_decompress(const uint8_t *data, size_t len,
                               uint8_t **out, size_t *out_len) {
    if (!data || len < 8 || !out || !out_len) return -1;

    /* Read MZLB header */
    uint32_t magic = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                     ((uint32_t)data[2] << 8) | data[3];
    if (magic != MOOR_COMPRESS_MAGIC) return -1;

    uint32_t uncomp_len = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16) |
                          ((uint32_t)data[6] << 8) | data[7];

    /* Sanity cap: 64 MB */
    if (uncomp_len > 64 * 1024 * 1024) return -1;

    *out = malloc(uncomp_len);
    if (!*out) return -1;

    uLongf dest_len = uncomp_len;
    int rc = uncompress(*out, &dest_len, data + 8, (uLong)(len - 8));
    if (rc != Z_OK) {
        free(*out);
        *out = NULL;
        return -1;
    }
    *out_len = (size_t)dest_len;
    return 0;
}

int moor_consensus_is_compressed(const uint8_t *data, size_t len) {
    if (!data || len < 4) return 0;
    uint32_t magic = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                     ((uint32_t)data[2] << 8) | data[3];
    return (magic == MOOR_COMPRESS_MAGIC) ? 1 : 0;
}
#endif /* !_WIN32 */
