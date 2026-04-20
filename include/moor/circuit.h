#ifndef MOOR_CIRCUIT_H
#define MOOR_CIRCUIT_H

#include <stdint.h>
#include <stddef.h>

/* Forward declarations */
struct moor_connection;
struct moor_channel;
struct moor_geoip_db;
typedef struct moor_geoip_db moor_geoip_db_t;
struct moor_bridge_entry;  /* from config.h */

typedef struct {
    uint16_t stream_id;
    int      target_fd;             /* Exit-side TCP connection */
    char     target_addr[256];
    uint16_t target_port;
    int      connected;
    int32_t  deliver_window;        /* Stream SENDME: cells we can accept */
    int32_t  package_window;        /* Stream SENDME: cells we can send */
    /* XON/XOFF flow control (Prop 344) */
    int      xoff_sent;             /* 1 if we sent XOFF (paused remote) */
    int      xoff_recv;             /* 1 if we received XOFF (remote paused us) */
    /* Half-closed state */
    int      half_closed;           /* 1 if we sent END but still reading */
    uint8_t  end_reason;            /* RELAY_END reason code */
} moor_stream_t;

/* Destroy reason codes (Tor-aligned) */
#define DESTROY_REASON_NONE             0
#define DESTROY_REASON_PROTOCOL         1
#define DESTROY_REASON_INTERNAL         2
#define DESTROY_REASON_CONNECTFAILED    3
#define DESTROY_REASON_RESOURCELIMIT    4
#define DESTROY_REASON_TIMEOUT          5
#define DESTROY_REASON_DESTROYED        6   /* received DESTROY from peer */
#define DESTROY_REASON_FINISHED         7   /* circuit no longer needed */

typedef struct moor_circuit {
    uint32_t circuit_id;

    /* ---- Tor-aligned mark-for-close (prevents ALL use-after-free) ----
     * Circuits are NEVER freed inline.  Instead, code calls
     * moor_circuit_mark_for_close() which sets these fields and adds
     * the circuit to a pending-close list.  The event loop calls
     * moor_circuit_close_all_marked() at a safe point (end of iteration)
     * to actually send DESTROY cells, close streams, and free the slot.
     *
     * While marked:
     *  - moor_circuit_find() returns NULL (circuit is invisible)
     *  - All cell processing skips this circuit
     *  - The slot is still valid memory, preventing UAF
     */
    uint16_t marked_for_close;           /* 0 = alive, >0 = line number where marked */
    const char *marked_for_close_file;   /* source file that marked it */
    uint8_t  marked_for_close_reason;    /* DESTROY_REASON_* */

    uint8_t  num_hops;
    struct {
        uint8_t forward_key[32];
        uint8_t backward_key[32];
        uint64_t forward_nonce;
        uint64_t backward_nonce;
        uint8_t forward_digest[32];     /* Running digest state */
        uint8_t backward_digest[32];
        uint8_t node_id[32];            /* Identity of this hop */
    } hops[3]; /* MOOR_CIRCUIT_HOPS */
    moor_connection_t *conn;            /* Link to first hop (guard) */
    struct moor_channel *chan;          /* Guard channel (owns conn, mux) */
    moor_stream_t streams[64];          /* MOOR_MAX_STREAMS */
    uint16_t next_stream_id;
    int      is_client;                 /* 1 if we originated this circuit */
    uint64_t created_at;
    /* For relay-side: previous hop connection and circuit_id */
    moor_connection_t *prev_conn;
    uint32_t prev_circuit_id;
    moor_connection_t *next_conn;
    uint32_t next_circuit_id;
    struct moor_channel *p_chan;        /* Previous hop channel (relay) */
    struct moor_channel *n_chan;        /* Next hop channel (relay) */
    /* Per-hop key for relay side (only one layer) */
    uint8_t  relay_forward_key[32];
    uint8_t  relay_backward_key[32];
    uint64_t relay_forward_nonce;
    uint64_t relay_backward_nonce;
    uint8_t  relay_forward_digest[32];
    uint8_t  relay_backward_digest[32];
    /* SENDME congestion control (legacy deliver side) */
    int32_t  circ_package_window;       /* Circuit-level: cells we can send */
    int32_t  circ_deliver_window;       /* Circuit-level: cells we can accept */
    /* RTT-based congestion control (Prop 324-style) */
    int      cc_state;                  /* CC_SLOW_START or CC_CONG_AVOIDANCE */
    int32_t  cwnd;                      /* congestion window (cells) */
    int32_t  ssthresh;                  /* slow start threshold */
    int32_t  inflight;                  /* cells sent but not yet ACK'd */
    uint64_t srtt_us;                   /* smoothed RTT in microseconds */
    uint64_t rtt_var_us;                /* RTT variance */
    uint64_t sendme_timestamps[20]; /* MOOR_CC_SENDME_TS_MAX: FIFO for RTT */
    uint8_t  sendme_ts_head;       /* next write position in circular buffer */
    uint8_t  sendme_ts_count;      /* number of pending timestamps */
    int      rtt_initialized;           /* have we measured at least one RTT? */
    /* Prop 324 Vegas CC fields */
    uint8_t  cc_path_type;         /* MOOR_CC_PATH_EXIT / ONION / SBWS */
    uint64_t min_rtt_us;           /* minimum observed RTT (queue-free estimate) */
    int64_t  bdp;                  /* bandwidth-delay product (cells) */
    int32_t  cwnd_full;            /* 1 if inflight reached cwnd since last SENDME */
    uint32_t sendme_ack_count;     /* total circuit-level SENDMEs received */
    /* Fragment reassembly state */
    moor_reassembly_state_t reassembly;
    /* PQ circuit-level crypto: per-hop Kyber state */
    int      pq_capable;                /* 1 if all hops support PQ */
    /* PQ: buffered KEM CT from CELL_KEM_CT or RELAY_KEM_OFFER (relay side) */
    uint8_t  pq_kem_ct[1088];           /* MOOR_KEM_CT_LEN */
    size_t   pq_kem_ct_len;             /* bytes received so far (0 = empty) */
    uint8_t  pq_key_seed[32];           /* DH key_seed preserved while awaiting KEM CT */
    int      pq_kem_pending;            /* 1 = waiting for CELL_KEM_CT to complete CREATE_PQ */
    struct moor_conflux_set *conflux;   /* Multi-path set (NULL if unused) */
    /* WTF-PAD adaptive padding state machine */
    wfpad_circuit_state_t wfpad_state;
    uint64_t last_cell_time;            /* Timestamp of last cell processed (OOM) */
    /* Intro point PoW: stored from ESTABLISH_INTRO for INTRODUCE1 verification */
    uint8_t  intro_pow_seed[32];
    uint8_t  intro_pow_difficulty;
    uint8_t  intro_service_pk[32];      /* blinded_pk from ESTABLISH_INTRO */
    /* Stream isolation: circuits tagged by SOCKS auth identity */
    char     isolation_key[256];
    /* SENDME authentication (Prop 289) */
#define MOOR_SENDME_AUTH_MAX 10
#define MOOR_SENDME_AUTH_LEN 20  /* Tor-aligned: 20-byte truncated digest */
    uint8_t  sendme_auth_expected[MOOR_SENDME_AUTH_MAX][MOOR_SENDME_AUTH_LEN];
    uint8_t  sendme_auth_head;          /* next write position in FIFO */
    uint8_t  sendme_auth_count;         /* pending expected digests */
    int32_t  sendme_auth_cells_sent;    /* backward cells sent since last record (relay) */
    /* Rendezvous point: partner circuit after RP join */
    struct moor_circuit *rp_partner;
    /* End-to-end encryption for HS rendezvous (fix #197) */
    uint8_t  e2e_send_key[32];
    uint8_t  e2e_recv_key[32];
    uint64_t e2e_send_nonce;
    uint64_t e2e_recv_nonce;
    int      e2e_active;           /* 1 if e2e keys are set */
    uint8_t  e2e_eph_sk[32];      /* Temp: client eph_sk for DH completion */
    /* PQ e2e: post-handshake Kyber768 KEM upgrade */
    uint8_t  e2e_kem_ct[1088];    /* Accumulating KEM ciphertext */
    uint16_t e2e_kem_ct_len;      /* Bytes received so far */
    int      e2e_kem_pending;     /* 1 = waiting for KEM CT / ACK */
    uint8_t  e2e_dh_shared[32];   /* Saved DH shared secret for hybrid KDF */
    /* SKIPS: per-circuit cell queues (pre-AEAD, relay-encrypted) */
    moor_circ_cell_queue_t cell_queue_n;  /* cells toward n_chan (forward) */
    moor_circ_cell_queue_t cell_queue_p;  /* cells toward p_chan (backward) */
    /* DoS cell rate limiting (Prop 305) */
    uint64_t dos_cell_tokens;           /* token bucket for cell rate */
    uint32_t relay_cells_queued;        /* Tor-aligned: per-circuit queue depth */
    uint64_t dos_cell_last_refill;      /* last refill timestamp (ms) */
    /* Bootstrap tracking */
    uint8_t  bootstrap_phase;           /* MOOR_BOOTSTRAP_* */
    /* Async circuit build context (non-NULL during build) */
    struct moor_cbuild_ctx *build_ctx;
    /* H3: Cumulative build deadline tracking */
    uint64_t build_started_ms;          /* timestamp when circuit build began */
    /* Async relay EXTEND: worker thread handles blocking connect+CREATE */
    int      extend_pending;            /* 1 if async EXTEND worker running */
    uint8_t  extend_client_eph_pk[32];  /* client ephemeral pk for CKE completion */
    /* RELAY_EARLY enforcement (Tor-aligned anti-extend-injection) */
    uint8_t  relay_early_count;         /* RELAY_EARLY cells seen on this circuit */
    /* Per-IP circuit accounting: stored on relay CREATE so we can decrement on free */
    uint32_t relay_peer_ipv4;           /* peer IPv4 (network order), 0 = unset */
} moor_circuit_t;

/* Circuit build state machine for non-blocking async building.
 * Flow: SEND cell → return to event loop → cell arrives via dispatch →
 * advance state → SEND next → repeat until 3 hops done. */
typedef enum {
    CBUILD_IDLE = 0,
    CBUILD_CONNECTING,          /* async TCP connect + Noise handshake */
    CBUILD_WAIT_CREATED,        /* sent CREATE, awaiting CELL_CREATED */
    CBUILD_WAIT_CREATED_PQ,     /* sent CREATE_PQ, awaiting CELL_CREATED_PQ */
    CBUILD_WAIT_EXTENDED_MID,   /* sent EXTEND to middle, awaiting RELAY_EXTENDED */
    CBUILD_WAIT_EXTENDED_EXIT,  /* sent EXTEND to exit, awaiting RELAY_EXTENDED */
    CBUILD_READY,
    CBUILD_FAILED,
} moor_cbuild_state_t;

typedef struct moor_cbuild_ctx {
    moor_cbuild_state_t state;
    moor_node_descriptor_t path[3];         /* guard, middle, exit */
    uint8_t  eph_pk[32], eph_sk[32];        /* current hop CKE ephemeral */
    uint8_t  relay_curve_pk[32];            /* current hop Curve25519 pk (pre-computed) */
    uint8_t  our_pk[32];
    uint8_t  our_sk[64];
    /* PQ hybrid state for current hop */
    uint8_t  kem_ct[1088];                  /* MOOR_KEM_CT_LEN */
    uint8_t  kem_ss[32];                    /* MOOR_KEM_SS_LEN */
    int      pq_hop;                        /* 1 if current hop uses PQ hybrid */
    /* Completion callback */
    void     (*on_complete)(moor_circuit_t *, int, void *);
    void     *on_complete_arg;
    uint64_t start_ms;
    int      cancelled;
    int      timeout_timer_id;              /* event timer for build deadline */
    int      timed_out;                     /* 1 if cbuild_timeout_cb fired */
} moor_cbuild_ctx_t;

/* Process incoming CREATED/CREATED_PQ for a building circuit.
 * Called from process_circuit_cell when a build response arrives. */
int moor_circuit_build_handle_created(moor_circuit_t *circ,
                                       const moor_cell_t *cell);

/* Process incoming RELAY_EXTENDED/EXTENDED_PQ for a building circuit.
 * Relay payload must already be decrypted and unpacked. */
int moor_circuit_build_handle_extended(moor_circuit_t *circ,
                                        uint8_t relay_cmd,
                                        const uint8_t *data, size_t len);

/* Prop 271-style guard selection: sampled/primary/confirmed guard sets */
#define MOOR_GUARD_SAMPLED_MAX   32
#define MOOR_GUARD_PRIMARY_MAX    3
#define MOOR_GUARD_CONFIRMED_MAX  8

typedef struct {
    uint8_t  identity_pk[32];
    char     address[64];
    uint16_t port;
    uint64_t added_at;          /* when first sampled */
    uint64_t confirmed_at;      /* when first confirmed (0=unconfirmed) */
    uint64_t last_tried;        /* last connection attempt */
    uint64_t unreachable_since; /* 0 = currently reachable */
    int      is_reachable;      /* last probe result */
    /* Path bias detection: track circuit success rate per guard */
    uint32_t pb_circ_attempts;  /* circuits attempted through this guard */
    uint32_t pb_circ_success;   /* circuits that completed successfully */
    uint32_t pb_use_attempts;   /* circuits used for streams */
    uint32_t pb_use_success;    /* circuits where stream succeeded */
    int      pb_suspect;        /* 1 if path bias flagged this guard */
    int      pb_disabled;       /* 1 if guard is disabled due to path bias */
} moor_guard_entry_t;

typedef struct {
    moor_guard_entry_t sampled[MOOR_GUARD_SAMPLED_MAX];
    int num_sampled;
    int primary_indices[MOOR_GUARD_PRIMARY_MAX];   /* indices into sampled[] */
    int num_primary;
    int confirmed_indices[MOOR_GUARD_CONFIRMED_MAX]; /* indices into sampled[], ordered by confirmed_at */
    int num_confirmed;
    char state_file[256];      /* persistence path */
} moor_guard_state_t;

/* Sample guards from consensus into sampled set */
int moor_guard_sample(moor_guard_state_t *state, const moor_consensus_t *consensus);

/* Update primary list from confirmed + sampled */
void moor_guard_update_primary(moor_guard_state_t *state);

/* Select best guard: primary[0] if reachable, else fallback */
const moor_guard_entry_t *moor_guard_select(const moor_guard_state_t *state);

/* Mark guard as reachable (on successful circuit) */
void moor_guard_mark_reachable(moor_guard_state_t *state, const uint8_t identity_pk[32]);

/* Mark guard as unreachable (on circuit failure) */
void moor_guard_mark_unreachable(moor_guard_state_t *state, const uint8_t identity_pk[32]);

/* Expire old sampled/confirmed entries */
void moor_guard_expire(moor_guard_state_t *state);

/* Path bias detection thresholds */
#define MOOR_PB_MIN_CIRCS          20   /* min circuits before judging */
#define MOOR_PB_NOTICE_RATE       0.70  /* below this: log notice */
#define MOOR_PB_WARN_RATE         0.50  /* below this: mark suspect */
#define MOOR_PB_EXTREME_RATE      0.30  /* below this: disable guard */
#define MOOR_PB_USE_NOTICE_RATE   0.80  /* stream-use success notice */
#define MOOR_PB_USE_EXTREME_RATE  0.50  /* stream-use: disable guard */
#define MOOR_PB_SCALE_AT          300   /* scale counts down at this many */

/* Record a circuit attempt/success/use through a guard */
void moor_pathbias_count_build_attempt(moor_guard_state_t *state,
                                        const uint8_t guard_pk[32]);
void moor_pathbias_count_build_success(moor_guard_state_t *state,
                                        const uint8_t guard_pk[32]);
void moor_pathbias_count_use_attempt(moor_guard_state_t *state,
                                      const uint8_t guard_pk[32]);
void moor_pathbias_count_use_success(moor_guard_state_t *state,
                                      const uint8_t guard_pk[32]);

/* Check path bias and flag/disable suspect guards. Called periodically. */
void moor_pathbias_check_all(moor_guard_state_t *state);

/* Get the global path bias guard state (for periodic checks) */
moor_guard_state_t *moor_pathbias_get_state(void);

int moor_guard_load(moor_guard_state_t *state, const char *data_dir);
int moor_guard_save(const moor_guard_state_t *state, const char *data_dir);

/* Vanguards: restricted middle hops for HS circuits */
typedef struct {
    uint8_t  relay_id[32];          /* Identity pk of vanguard relay */
    uint64_t selected_at;
    uint64_t expires_at;
    int      valid;
} moor_vanguard_relay_t;

typedef struct {
    moor_vanguard_relay_t l2[4];    /* MOOR_VANGUARD_L2_COUNT */
    int                   num_l2;
    moor_vanguard_relay_t l3[8];    /* MOOR_VANGUARD_L3_COUNT */
    int                   num_l3;
} moor_vanguard_set_t;

/* Initialize vanguard set from consensus, rotating expired ones */
int moor_vanguard_init(moor_vanguard_set_t *vg,
                       const moor_consensus_t *consensus,
                       const uint8_t *exclude_ids, int num_exclude);

/* Select a layer-2 vanguard for HS circuit middle hop */
const moor_node_descriptor_t *moor_vanguard_select_l2(
    const moor_vanguard_set_t *vg,
    const moor_consensus_t *consensus,
    const uint8_t *exclude_ids, int num_exclude);

/* Select a layer-3 vanguard for HS circuit third hop */
const moor_node_descriptor_t *moor_vanguard_select_l3(
    const moor_vanguard_set_t *vg,
    const moor_consensus_t *consensus,
    const uint8_t *exclude_ids, int num_exclude);

/* Persist/load vanguard set */
int moor_vanguard_save(const moor_vanguard_set_t *vg, const char *data_dir);
int moor_vanguard_load(moor_vanguard_set_t *vg, const char *data_dir);

/* Set global GeoIP database for diverse path selection */
void moor_circuit_set_geoip(moor_geoip_db_t *db);

/* Initialize circuit pool */
void moor_circuit_init_pool(void);

/* Allocate a circuit */
moor_circuit_t *moor_circuit_alloc(void);

/* Free a circuit slot (internal — prefer mark_for_close in all new code) */
void moor_circuit_free(moor_circuit_t *circ);

/* ---- Tor-aligned deferred close API ----
 * NEVER free circuits inline.  Always mark, then the event loop frees.
 * This eliminates use-after-free: the slot stays valid until no code
 * can possibly hold a reference to it. */

/* Mark a circuit for deferred close. The circuit becomes invisible to
 * moor_circuit_find() immediately but is not freed until
 * moor_circuit_close_all_marked() runs at end of event loop. */
void moor_circuit_mark_for_close_(moor_circuit_t *circ, uint8_t reason,
                                   int line, const char *file);
#define moor_circuit_mark_for_close(circ, reason) \
    moor_circuit_mark_for_close_((circ), (reason), __LINE__, __FILE__)

/* Check if a circuit is marked for close */
#define MOOR_CIRCUIT_IS_MARKED(circ) ((circ)->marked_for_close != 0)

/* Process all pending close operations.  Called from event loop
 * at end of each iteration — sends DESTROY cells, closes streams,
 * wipes crypto, frees circuit slots.  NEVER call from a callback. */
void moor_circuit_close_all_marked(void);

/* Mark ALL circuits on a dying connection for close.
 * Tor-aligned: when a channel dies, every circuit on it gets marked.
 * This replaces the old teardown_for_conn which freed circuits inline. */
void moor_circuit_mark_all_for_conn(moor_connection_t *conn, uint8_t reason);

/* NULL out all circuit references to a dying connection */
void moor_circuit_nullify_conn(moor_connection_t *conn);
/* Check if any circuit references this connection */
int moor_circuit_conn_in_use(moor_connection_t *conn);

/* Legacy teardown — calls mark_all_for_conn now (kept for compatibility) */
void moor_circuit_teardown_for_conn(moor_connection_t *conn);

/* Register/unregister circuit in the hash table (must call after setting conn/prev_conn/next_conn) */
void moor_circuit_register(moor_circuit_t *circ);
void moor_circuit_unregister(moor_circuit_t *circ);
void moor_circuit_adopt(moor_circuit_t *circ);  /* adopt worker circuit into main thread */

/* Find circuit by circuit_id on a given connection (O(1) hash table lookup) */
moor_circuit_t *moor_circuit_find(uint32_t circuit_id,
                                  const moor_connection_t *conn);

/* Find the ESTABLISH_INTRO circuit matching the given blinded_pk.
 * If blinded_pk is NULL, falls back to finding any circuit with
 * intro_service_pk set (legacy compat).  Excludes the given circuit. */
moor_circuit_t *moor_circuit_find_by_intro_pk(const moor_circuit_t *exclude,
                                               const uint8_t *blinded_pk);

/* Build a 3-hop circuit through the network.
 * Selects guard, middle, exit from consensus.
 * skip_guard_reuse: if 1, always create fresh guard connection (for builder thread).
 * Returns 0 on success. */
int moor_circuit_build(moor_circuit_t *circ,
                       moor_connection_t *guard_conn,
                       const moor_consensus_t *consensus,
                       const uint8_t our_identity_pk[32],
                       const uint8_t our_identity_sk[64],
                       int skip_guard_reuse);

/* Build a 3-hop circuit via a bridge (pluggable transport).
 * Uses bridge as first hop instead of consensus guard.
 * Returns 0 on success. */
int moor_circuit_build_bridge(moor_circuit_t *circ,
                              moor_connection_t *bridge_conn,
                              const moor_consensus_t *consensus,
                              const uint8_t our_identity_pk[32],
                              const uint8_t our_identity_sk[64],
                              const struct moor_bridge_entry *bridge,
                              int skip_reuse);

/* Perform CREATE handshake for first hop.
 * relay_identity_pk = Ed25519 (for identification + HKDF binding)
 * relay_onion_pk    = Curve25519 (for static DH — rotatable, forward secrecy) */
int moor_circuit_create(moor_circuit_t *circ,
                        const uint8_t relay_identity_pk[32],
                        const uint8_t relay_onion_pk[32]);

/* Perform PQ hybrid CREATE handshake: X25519 + Kyber768.
 * relay_kem_pk is the relay's Kyber768 public key from consensus.
 * Sends KEM ciphertext after CREATED_PQ for post-quantum key agreement. */
int moor_circuit_create_pq(moor_circuit_t *circ,
                           const uint8_t relay_identity_pk[32],
                           const uint8_t relay_onion_pk[32],
                           const uint8_t relay_kem_pk[1184]);

/* Handle incoming CREATED cell */
int moor_circuit_handle_created(moor_circuit_t *circ,
                                const moor_cell_t *cell);

/* Extend circuit to next hop */
int moor_circuit_extend(moor_circuit_t *circ,
                        const moor_node_descriptor_t *next_relay);

/* Extend circuit with PQ hybrid: X25519 + Kyber768.
 * KEM ciphertext is sent via RELAY_KEM_OFFER after RELAY_EXTEND_PQ. */
int moor_circuit_extend_pq(moor_circuit_t *circ,
                           const moor_node_descriptor_t *next_relay);

/* Handle incoming EXTENDED relay cell */
int moor_circuit_handle_extended(moor_circuit_t *circ,
                                 const uint8_t *payload, size_t len);

/* Encrypt a relay cell with all circuit layers (client sending toward exit) */
int moor_circuit_encrypt_forward(moor_circuit_t *circ, moor_cell_t *cell);

/* Decrypt a relay cell removing all layers (client receiving from exit) */
int moor_circuit_decrypt_backward(moor_circuit_t *circ, moor_cell_t *cell);

/* Relay-side: decrypt one layer (forward direction) */
int moor_circuit_relay_decrypt(moor_circuit_t *circ, moor_cell_t *cell);

/* Relay-side: encrypt one layer (backward direction) */
int moor_circuit_relay_encrypt(moor_circuit_t *circ, moor_cell_t *cell);

/* Open a stream on this circuit */
int moor_circuit_open_stream(moor_circuit_t *circ, uint16_t *stream_id,
                             const char *addr, uint16_t port);

/* Resolve hostname through circuit exit (Tor-aligned RELAY_RESOLVE).
 * Returns IPv4 in network byte order, or 0 on failure. Blocking. */
uint32_t moor_circuit_resolve(moor_circuit_t *circ, const char *hostname);

/* Find stream by id */
moor_stream_t *moor_circuit_find_stream(moor_circuit_t *circ,
                                        uint16_t stream_id);

/* Send data on a stream */
int moor_circuit_send_data(moor_circuit_t *circ, uint16_t stream_id,
                           const uint8_t *data, size_t len);

/* SENDME congestion control */
int moor_circuit_handle_sendme(moor_circuit_t *circ, uint16_t stream_id,
                               const uint8_t *sendme_data, uint16_t sendme_len);
int moor_circuit_maybe_send_sendme(moor_circuit_t *circ, uint16_t stream_id);

/* Async circuit build: non-blocking, fires callback on completion.
 * Returns 0 if build started, -1 on immediate failure. */
int moor_circuit_build_async(moor_circuit_t *circ,
                              moor_connection_t *conn,
                              const moor_consensus_t *cons,
                              const uint8_t our_pk[32],
                              const uint8_t our_sk[64],
                              void (*on_complete)(moor_circuit_t *, int, void *),
                              void *arg);

/* Cancel an in-progress async build */
void moor_circuit_build_cancel(moor_circuit_t *circ);
void moor_circuit_build_abort(moor_circuit_t *circ);

/* Tear down circuit (now deferred — calls mark_for_close internally) */
int moor_circuit_destroy(moor_circuit_t *circ);

/* Check all circuits for timeouts (incomplete > 60s, established > 600s) */
void moor_circuit_check_timeouts(void);

/* Generate a random circuit ID */
uint32_t moor_circuit_gen_id(void);

/* Padding machines: inject CELL_PADDING on active circuits */
void moor_padding_enable(int enabled);
void moor_padding_send_all(void);    /* Called by timer: pad all active circuits */
uint64_t moor_padding_next_interval(void); /* Random interval in ms */

/* OOM circuit killer: kill idle/oldest circuits to free slots */
int moor_circuit_oom_kill(int target_free);

/* Count active circuits (dynamic — no hard cap) */
int moor_circuit_active_count(void);

/* Iteration API: access circuits by index (for main.c, padding, etc.) */
int moor_circuit_iter_count(void);
moor_circuit_t *moor_circuit_iter_get(int idx);

/* Circuit Build Timeout (CBT): adaptive timeout from Pareto distribution */
#define MOOR_CBT_MAX_SAMPLES   100
#define MOOR_CBT_MIN_SAMPLES   20
#define MOOR_CBT_QUANTILE_PCT  80    /* target 80th percentile */
#define MOOR_CBT_TIMEOUT_MIN   10000 /* 10s minimum (ms) */
#define MOOR_CBT_TIMEOUT_MAX   120000 /* 120s maximum (ms) */

typedef struct {
    uint64_t build_times_ms[MOOR_CBT_MAX_SAMPLES];
    int      num_samples;
    int      next_idx;           /* circular buffer index */
    uint64_t timeout_ms;         /* computed adaptive timeout */
    int      using_adaptive;     /* 1 if enough samples collected */
} moor_cbt_state_t;

void moor_cbt_init(moor_cbt_state_t *cbt);
void moor_cbt_record(moor_cbt_state_t *cbt, uint64_t build_time_ms);
uint64_t moor_cbt_get_timeout(const moor_cbt_state_t *cbt);

/* Bootstrap state machine */
#define MOOR_BOOTSTRAP_STARTING         0
#define MOOR_BOOTSTRAP_CONN_DA          1
#define MOOR_BOOTSTRAP_LOADING_KEYS     2
#define MOOR_BOOTSTRAP_FETCHING_CONS    3
#define MOOR_BOOTSTRAP_LOADING_CONS     4
#define MOOR_BOOTSTRAP_ENOUGH_RELAYS    5
#define MOOR_BOOTSTRAP_BUILDING_CIRCS   6
#define MOOR_BOOTSTRAP_DONE             7

typedef struct {
    uint8_t  phase;
    uint8_t  pct;               /* 0-100 */
    uint64_t phase_start_ms;
} moor_bootstrap_state_t;

void moor_bootstrap_init(moor_bootstrap_state_t *bs);
void moor_bootstrap_advance(moor_bootstrap_state_t *bs, uint8_t phase);
uint8_t moor_bootstrap_pct(const moor_bootstrap_state_t *bs);

/* Pre-emptive circuit pool */
#define MOOR_PREEMPTIVE_MIN  3   /* keep at least 3 clean circuits ready */
int moor_circuit_preemptive_count(void);
/* Tag a circuit with an isolation key */
void moor_circuit_set_isolation(moor_circuit_t *circ, const char *key);

/* DoS cell rate limiting (Prop 305) */
int moor_dos_cell_check_circuit(moor_circuit_t *circ);
int moor_dos_cell_check_conn(moor_connection_t *conn);

/* Stream isolation: find circuit by isolation key */
moor_circuit_t *moor_circuit_find_by_isolation(const char *key);

/* NETINFO cell exchange */
int moor_send_netinfo(moor_connection_t *conn);
int moor_handle_netinfo(const moor_cell_t *cell, int64_t *clock_skew_out);

/* Canonical connection reuse */
moor_connection_t *moor_connection_find_or_connect(
    const uint8_t peer_id[32],
    const char *address, uint16_t port,
    const uint8_t our_pk[32], const uint8_t our_sk[64]);

/* EXTEND link specifiers */
#define MOOR_LSPEC_IPV4     0   /* 4 bytes addr + 2 bytes port = 6 */
#define MOOR_LSPEC_IPV6     1   /* 16 bytes addr + 2 bytes port = 18 */
#define MOOR_LSPEC_ED25519  2   /* 32 bytes identity */

int moor_lspec_encode(uint8_t *buf, size_t buf_len,
                       const char *address, uint16_t port,
                       const uint8_t identity_pk[32]);
int moor_lspec_decode(const uint8_t *buf, size_t buf_len,
                       char *address, size_t addr_len,
                       uint16_t *port, uint8_t identity_pk[32]);

#endif /* MOOR_CIRCUIT_H */
