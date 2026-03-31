/*
 * MOOR -- Consolidated limit definitions
 *
 * All capacity, count, and size limits in one place.
 * Categories:
 *   PROTOCOL -- Fixed by wire format; changing breaks compatibility.
 *   TUNABLE  -- Can be adjusted via consensus or config.
 *   INTERNAL -- Implementation limits; can be changed with recompile.
 */
#ifndef MOOR_LIMITS_H
#define MOOR_LIMITS_H

/* ===== PROTOCOL-FIXED (wire format) ===== */
#define MOOR_CELL_SIZE          514     /* Fixed cell size on wire */
#define MOOR_CELL_HEADER        5       /* circuit_id(4) + command(1) */
#define MOOR_CELL_PAYLOAD       509     /* MOOR_CELL_SIZE - MOOR_CELL_HEADER */
#define MOOR_RELAY_HEADER       11      /* relay_cmd(1)+recognized(2)+stream_id(2)+digest(4)+length(2) */
#define MOOR_RELAY_DATA         498     /* MOOR_CELL_PAYLOAD - MOOR_RELAY_HEADER */
#define MOOR_CIRCUIT_HOPS       3       /* Fixed 3-hop circuit topology */
#define MOOR_SENDME_INCREMENT   100     /* Cells between SENDMEs */

/* ===== TUNABLE (runtime or consensus) ===== */
#define MOOR_CIRCUIT_WINDOW     1000    /* Circuit-level SENDME window */
#define MOOR_STREAM_WINDOW      100     /* Stream-level SENDME window */
#define MOOR_PADDING_MIN_MS     100     /* Min padding interval */
#define MOOR_PADDING_MAX_MS     1000    /* Max padding interval */

/* ===== INTERNAL -- Pools & Capacity ===== */
#define MOOR_MAX_RELAYS         8192    /* Max relays in consensus */
#define MOOR_MAX_CIRCUITS       1024    /* Max active circuits */
#define MOOR_MAX_CONNECTIONS    1024    /* Max TCP connections */
#define MOOR_MAX_STREAMS        64      /* Max streams per circuit */
#define MOOR_MAX_INTRO_POINTS   10      /* Max intro points per HS (Tor: 3-10) */
#define MOOR_DEFAULT_INTRO_POINTS 6    /* Default intro points per HS (Tor default: 6) */
#define MOOR_MAX_DA_AUTHORITIES 9       /* Max directory authorities */
#define MOOR_MAX_EXIT_RULES     64      /* Max exit policy rules */
#define MOOR_MAX_HIDDEN_SERVICES 8      /* Max HS instances per relay */
#define MOOR_MAX_BRIDGES        8       /* Max bridges for client */
#define MOOR_MAX_FALLBACKS      16      /* Max fallback DA servers */
#define MOOR_MAX_TRANSPORTS     4       /* Max pluggable transports */

/* ===== INTERNAL -- File Descriptors ===== */
#if defined(__linux__) && !defined(MOOR_NO_EPOLL)
#define MOOR_USE_EPOLL
#define MOOR_MAX_FDS            8192
#else
#define MOOR_MAX_FDS            1024
#endif

/* ===== INTERNAL -- Timing ===== */
#define MOOR_CIRCUIT_TIMEOUT        60      /* Circuit build timeout (seconds) */
#define MOOR_HANDSHAKE_TIMEOUT      30      /* Link handshake timeout (seconds) */
#define MOOR_DA_REQUEST_TIMEOUT     10      /* DA request timeout (seconds) */
#define MOOR_CONSENSUS_INTERVAL     3600    /* Consensus publish interval (seconds) */
#define MOOR_CIRCUIT_ROTATE_SECS    600     /* Circuit rotation period (seconds) */
#define MOOR_RELAY_CIRCUIT_MAX_AGE  86400  /* Relay-side max circuit lifetime (24h) */
#define MOOR_GUARD_ROTATE_DAYS      120     /* Guard rotation (days) */
#define MOOR_TIME_PERIOD_SECS       86400   /* Key blinding rotation (24h) */
#define MOOR_VANGUARD_L2_ROTATE     86400   /* L2 vanguard rotation (24h) */
#define MOOR_VANGUARD_L3_ROTATE     3600    /* L3 vanguard rotation (1h) */

/* ===== INTERNAL -- Congestion Control (Prop 324 / Vegas) ===== */
#define MOOR_CC_CWND_INIT           124     /* Initial congestion window */
#define MOOR_CC_CWND_MIN            31      /* Minimum congestion window */
#define MOOR_CC_CWND_MAX            2000    /* Maximum congestion window */
#define MOOR_CC_SSTHRESH_INIT       1000    /* Initial slow-start threshold */
#define MOOR_CC_VEGAS_ALPHA         30      /* Vegas alpha threshold */
#define MOOR_CC_VEGAS_BETA          100     /* Vegas beta threshold */
#define MOOR_CC_VEGAS_GAMMA         50      /* Vegas gamma (SS exit) */
#define MOOR_CC_VEGAS_DELTA         10      /* Vegas delta (cwnd adjust) */

/* ===== INTERNAL -- DoS Protection ===== */
#define MOOR_DOS_CELL_RATE_PER_CIRCUIT  100     /* Cells/sec per circuit */
#define MOOR_DOS_CELL_BURST_PER_CIRCUIT 200     /* Burst per circuit */
#define MOOR_DOS_CELL_RATE_PER_CONN     1000    /* Cells/sec per connection */
#define MOOR_DOS_CELL_BURST_PER_CONN    2000    /* Burst per connection */
#define MOOR_POW_DEFAULT_DIFFICULTY     8       /* PoW leading zero bits (Argon2id) */
#define MOOR_POW_TIMESTAMP_WINDOW       3600    /* PoW validity (1h) */
#define MOOR_POW_MEMLIMIT_DEFAULT       (256U * 1024U)  /* Argon2id memory: 256 KB */
#define MOOR_POW_MEMLIMIT_MIN           (8U * 1024U)
#define MOOR_POW_MEMLIMIT_MAX           (64U * 1024U * 1024U)  /* 64 MB */
#define MOOR_POW_OPSLIMIT              1       /* Argon2id ops (1 pass) */

/* ===== INTERNAL -- OOM ===== */
#define MOOR_OOM_HIGH_WATER     768     /* OOM killer threshold (75% of MAX_CIRCUITS) */
#define MOOR_OOM_IDLE_SECS      60      /* OOM idle cleanup interval */

#endif /* MOOR_LIMITS_H */
