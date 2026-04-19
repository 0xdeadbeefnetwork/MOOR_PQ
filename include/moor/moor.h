/*
 * MOOR -- Anonymous Overlay Network
 * As dark as it gets.
 *
 * Error handling contract:
 *   - Functions returning int: 0 = success, -1 = fatal error.
 *   - Functions returning pointers: NULL = error.
 *   - Callers MUST check return values of all crypto and I/O operations.
 *   - Cleanup/free functions return void and are always safe to call.
 *   - All secret key material on the stack MUST be wiped with
 *     sodium_memzero() or moor_crypto_wipe() before function return,
 *     including all error paths.
 */
#ifndef MOOR_H
#define MOOR_H

#include <stdint.h>
#include <stddef.h>
#include "moor/limits.h"
#include "moor/debug.h"

#define MOOR_VERSION_MAJOR  0
#define MOOR_VERSION_MINOR  8
#define MOOR_VERSION_PATCH  1
#define MOOR_VERSION_STRING "0.8.1"

/* Identity / key lengths (protocol-fixed, crypto algorithm sizes) */
#define MOOR_ID_LEN             32      /* Ed25519 public key */
#define MOOR_SK_LEN             64      /* Ed25519 secret key */
#define MOOR_ONION_KEY_LEN      32      /* Curve25519 public key */
#define MOOR_ONION_SK_LEN      32      /* Curve25519 secret key */
#define MOOR_SIG_LEN            64      /* Ed25519 signature */
#define MOOR_ADDR_LEN           58      /* base32(pk) + ".moor" */
#define MOOR_SEAL_OVERHEAD      48      /* crypto_box_seal overhead */
#define MOOR_HASH_LEN           32      /* BLAKE2b-256 */
#define MOOR_SYM_KEY_LEN        32      /* ChaCha20-Poly1305 key */
#define MOOR_NONCE_LEN          8       /* 64-bit nonce (xchacha uses 24 but we use counter) */
#define MOOR_MAC_LEN            16      /* Poly1305 tag */
#define MOOR_KX_PK_LEN          32      /* crypto_kx public key */
#define MOOR_KX_SK_LEN          32      /* crypto_kx secret key */
#define MOOR_RENDEZVOUS_COOKIE_LEN 20

/* Vanguard counts */
#define MOOR_VANGUARD_L2_COUNT  4       /* Number of layer-2 vanguard relays */
#define MOOR_VANGUARD_L3_COUNT  8       /* Number of layer-3 vanguard relays */
#define MOOR_PADDING_ENABLED    1       /* Default: ON (mandatory baseline) */

/* Traffic analysis resistance constants */
#define MOOR_TA_CONSTANT_RATE_MS  20    /* Constant-rate floor: 50 cells/sec */
#define MOOR_TA_FRONT_SIGMA       400   /* Rayleigh sigma for FRONT padding */
#define MOOR_TA_FRONT_MAX         1000  /* Max FRONT padding cells per circuit */
#define MOOR_TA_FRONT_WINDOW_MS   5000  /* Spread FRONT cells over 5 seconds */

/* Bandwidth verification */
#define MOOR_BW_TEST_SIZE       (256 * 1024) /* 256KB test */
#define MOOR_BW_TOLERANCE       1.2          /* 20% tolerance */

/* Conflux multi-path */
#define MOOR_CONFLUX_MAX_LEGS   4       /* Max circuits per conflux set */
#define MOOR_CONFLUX_REORDER_BUF 32     /* Reorder buffer slots */

/* HS intro point rotation.
 *
 * Intro circuits silently rot from the HS's POV: if the intro-point relay
 * restarts or forgets our ESTABLISH_INTRO, our TCP link through hop1/hop2
 * still looks OPEN and we have no way to detect the loss.  Clients keep
 * picking the dead intro because its circuit-build succeeds, but their
 * INTRODUCE1 vanishes at hop-3.  Dropping lifetime to 1h caps the worst-case
 * downtime between rotations.  With rotation_cb ticking every 10s (see
 * main.c), replacement intros spin up well before clients notice. */
#define MOOR_HS_INTRO_MAX_LIFETIME_SEC  3600  /* 1 hour — was 18h, silent stale-out */
#define MOOR_HS_INTRO_MAX_INTRODUCTIONS 16384
#define MOOR_HS_INTRO_NUM_EXTRA         2     /* build 2 extra for rotation */

/* Consensus parameters (tunable via consensus) */
#define MOOR_MAX_CONSENSUS_PARAMS  32

/* Protocol version: bump whenever the descriptor wire format or signing
 * changes.  DAs reject descriptors below MOOR_MIN_PROTOCOL_VERSION.
 * This prevents old binaries from joining the network and causing
 * signature verification failures during DA-to-DA sync. */
#define MOOR_PROTOCOL_VERSION       4   /* v0.8.2: adds build_id (V7) to descriptor */
#define MOOR_MIN_PROTOCOL_VERSION   4   /* minimum accepted by DAs */

/* Length of the git-commit build identifier carried in every descriptor.
 * 12 hex chars + space for NUL/padding.  Populated from moor_build_id
 * (see src/build_id.c).  Strict equality is enforced at DAs. */
#define MOOR_BUILD_ID_LEN           16

/* Exported by src/build_id.c — always rebuilt so it reflects current HEAD. */
extern const char moor_build_id[MOOR_BUILD_ID_LEN];

/* Node descriptor features bitmask */
#define NODE_FEATURE_PQ         (1u << 0)  /* Supports PQ circuit crypto */
#define NODE_FEATURE_FAMILY     (1u << 1)  /* Has relay family declarations */
#define NODE_FEATURE_NICKNAME   (1u << 2)  /* Has nickname + key rotation (V4) */
#define NODE_FEATURE_CONTACT    (1u << 3)  /* Has operator contact info (V5) */
#define NODE_FEATURE_CELL_KEM   (1u << 4)  /* KEM CT via CELL_KEM_CT (v0.8+) */
#define NODE_FEATURE_BUILD_ID   (1u << 5)  /* Descriptor carries 16-byte build_id (v0.8.2) */

/* Minimum required feature set for DA to accept a relay descriptor.
 * Old nodes without CELL_KEM cause wire framing desync on the network.
 * BUILD_ID is required so we can enforce strict fleet-wide commit equality. */
#define NODE_FEATURES_REQUIRED  (NODE_FEATURE_CELL_KEM | NODE_FEATURE_BUILD_ID)

/* Node flags */
#define NODE_FLAG_GUARD         (1u << 0)
#define NODE_FLAG_EXIT          (1u << 1)
#define NODE_FLAG_STABLE        (1u << 2)
#define NODE_FLAG_FAST          (1u << 3)
#define NODE_FLAG_RUNNING       (1u << 4)
#define NODE_FLAG_VALID         (1u << 5)
#define NODE_FLAG_AUTHORITY     (1u << 6)
#define NODE_FLAG_BADEXIT       (1u << 7)
#define NODE_FLAG_MIDDLEONLY    (1u << 8)
#define NODE_FLAG_HSDIR         (1u << 9)   /* Suitable for HS descriptor storage */

/* Flags assigned by DA (not signed by relay) — must be stripped for sig verify
 * and excluded from consensus body hash (so all DAs produce identical hashes) */
#define NODE_FLAGS_DA_ASSIGNED  (NODE_FLAG_FAST | NODE_FLAG_STABLE | NODE_FLAG_BADEXIT | \
                                 NODE_FLAG_HSDIR)

/* Defaults */
#define MOOR_DEFAULT_SOCKS_PORT     9050
#define MOOR_DEFAULT_OR_PORT        9001
#define MOOR_DEFAULT_DIR_PORT       9030

/* Congestion control (Prop 324-style) */
#define MOOR_CC_SLOW_START      0
#define MOOR_CC_CONG_AVOIDANCE  1
#define MOOR_CC_SS_RTT_EXIT_PCT 50    /* exit slow start if RTT > min*(100+PCT)/100 */
#define MOOR_CC_SENDME_TS_MAX  20    /* max pending SENDME timestamps (FIFO) */

/* Path-type-specific CC constants (matches Tor's per-path tuning) */
#define MOOR_CC_PATH_EXIT     0   /* Normal 3-hop exit circuit */
#define MOOR_CC_PATH_ONION    1   /* 6-hop onion service circuit */
#define MOOR_CC_PATH_SBWS     2   /* 2-hop bandwidth measurement */
#define MOOR_CC_PATH_COUNT    3

/* Per-path-type Vegas constants: {alpha, beta, gamma, delta}
 * Exit (3-hop):  moderate thresholds, shorter queue budget
 * Onion (6-hop): wider thresholds, more queue tolerance (longer path = more variance)
 * SBWS (2-hop):  tight thresholds, aggressive measurement */
typedef struct {
    int32_t alpha;   /* queue < alpha → cwnd increase */
    int32_t beta;    /* queue > beta → cwnd decrease */
    int32_t gamma;   /* slow start exit threshold */
    int32_t delta;   /* cwnd adjustment step */
} moor_cc_params_t;

/* Modes */
typedef enum {
    MOOR_MODE_CLIENT = 0,
    MOOR_MODE_RELAY,
    MOOR_MODE_DA,       /* Directory Authority */
    MOOR_MODE_HS,       /* Hidden Service */
    MOOR_MODE_OB,       /* OnionBalance master */
    MOOR_MODE_BRIDGEDB,    /* Bridge distribution service */
    MOOR_MODE_BRIDGE_AUTH, /* Bridge authority */
} moor_mode_t;

/* Error codes */
typedef enum {
    MOOR_OK = 0,
    MOOR_ERR = -1,
    MOOR_ERR_CRYPTO = -2,
    MOOR_ERR_NETWORK = -3,
    MOOR_ERR_PROTOCOL = -4,
    MOOR_ERR_NOMEM = -5,
    MOOR_ERR_FULL = -6,
    MOOR_ERR_TIMEOUT = -7,
    MOOR_ERR_BADARG = -8,
} moor_err_t;

/* Include all sub-headers */
#include "log.h"
#include "crypto.h"
#include "sig.h"
#include "falcon.h"
#include "cell.h"
#include "node.h"
#include "kem.h"
#include "fragment.h"
#include "transport.h"
#include "transport_scramble.h"
#include "scheduler.h"
#include "connection.h"
#include "wfpad.h"
#include "channel.h"
#include "circuit.h"
#include "config.h"
#include "pow.h"
#include "geoip.h"
#include "bw_auth.h"
#include "conflux.h"
#include "ratelimit.h"
#include "relay.h"
#include "directory.h"
#include "socks5.h"
#include "hidden_service.h"
#include "onionbalance.h"
#include "bridgedb.h"
#include "event.h"
#include "monitor.h"
#include "dns_cache.h"
#include "bootstrap.h"
#include "transparent.h"
#include "addressmap.h"
#include "bridge_auth.h"
#include "exit_sla.h"
#include "transport_shade.h"
#include "transport_mirage.h"
#include "transport_shitstorm.h"
#include "transport_speakeasy.h"
#include "transport_nether.h"
#include "dht.h"
#include "mix.h"
#include "dns_server.h"
#include "exit_notice.h"

#endif /* MOOR_H */
