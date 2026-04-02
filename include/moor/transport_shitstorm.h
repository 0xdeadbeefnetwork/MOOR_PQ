/*
 * MOOR -- ShitStorm Transport
 *
 * Layered defense combining the strongest features of all three transports:
 *
 *   Mirage:  TLS 1.3 record framing, real x25519 key_share in ClientHello,
 *            session_id HMAC probing defense, static-DH MITM resistance,
 *            fake encrypted handshake records, configurable SNI, first-record
 *            padding to 1400-1500 bytes.
 *
 *   Shade:   Elligator2 constant-time key generation (pool of 32 pre-generated
 *            representable keys), 256-entry replay cache with 600s TTL.
 *
 *   Scramble: Double-DH key derivation (auth DH + transport DH), length
 *             obfuscation (XOR with ChaCha20 keystream on 2-byte length header
 *             inside app data records), random inner padding.
 *
 * Novel features beyond any single transport:
 *   1. x25519 key in TLS key_share is Elligator2-representable.
 *   2. Triple authentication: session_id HMAC + static-DH + replay cache.
 *   3. Double encryption: TLS app data records contain ChaCha20-Poly1305
 *      encrypted payloads with XOR-obfuscated length headers.
 *   4. Combined anti-fingerprinting: TLS framing + Elligator2 keys +
 *      first-record padding + fake HS records + variable inner padding.
 */
#ifndef MOOR_TRANSPORT_SHITSTORM_H
#define MOOR_TRANSPORT_SHITSTORM_H

#include "transport.h"

/* Client params: relay identity for HMAC session_id + static-DH MITM resistance */
typedef struct {
    char     sni[256];         /* Server Name Indication (random if empty) */
    uint8_t  identity_pk[32];  /* Relay's Ed25519 public key (node_id) */
} moor_shitstorm_client_params_t;

/* Server params: our identity keypair for session_id verification + static-DH */
typedef struct {
    uint8_t  identity_pk[32];  /* Our Ed25519 public key */
    uint8_t  identity_sk[64];  /* Our Ed25519 secret key */
} moor_shitstorm_server_params_t;

/* Pluggable transport instance */
extern const moor_transport_t moor_shitstorm_transport;

/*
 * Auto-discover CDN domains with edge servers in the caller's country.
 *
 * Used by BOTH bridge relays and clients:
 *   - Bridge: pass the bridge's advertise address as our_public_ip
 *   - Client: pass NULL to auto-detect public IP via ip-api.com
 *
 * Strategy:
 * 1. Determine country from public IP (auto-detect, GeoIP DB, or ip-api.com)
 * 2. Resolve a large list of global CDN domains via system DNS
 * 3. GeoIP-check each resolved IP
 * 4. Keep domains whose edge servers are in our country
 * 5. Set those as the SNI pool for both ShitStorm and Mirage transports
 *
 * For clients, this is critical: DPI happens on the CLIENT side.  If a
 * client in Iran connects to a US bridge, the Iranian ISP's DPI sees the
 * SNI.  It must be a CDN with Iranian edge servers, not US ones.
 *
 * @param our_public_ip  Public IP (dotted-quad), or NULL to auto-detect
 * @param geoip_db       Loaded GeoIP database (may be NULL; uses ip-api.com fallback)
 * @param data_dir       Data directory for caching results (may be NULL/empty)
 * @param is_bridge      1 if called from bridge relay, 0 if client.
 *                        Client side skips all plaintext HTTP queries
 *                        (Shodan, ip-api.com) to avoid ISP fingerprinting.
 */
void moor_shitstorm_discover_local_snis(const char *our_public_ip,
                                        const moor_geoip_db_t *geoip_db,
                                        const char *data_dir,
                                        int is_bridge);

#endif /* MOOR_TRANSPORT_SHITSTORM_H */
