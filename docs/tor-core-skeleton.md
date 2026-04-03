# Tor Core Architecture Skeleton

Complete analysis of `tor-0.4.9.6/src/core/` — 69,000 lines across 130+ files.

## Layer Architecture

```
APPLICATION LAYER
  proto_socks.c -----> SOCKS5 parsing (greeting, auth, request)
  proto_http.c ------> HTTP directory protocol
  proto_cell.c ------> Cell wire format parsing
  connection_edge.c -> Stream management (5044 lines, 100+ functions)

CIRCUIT LAYER
  circuitbuild.c ----> Path selection + CREATE/EXTEND cells
  circuitlist.c -----> Global circuit registry + mark_for_close
  circuituse.c ------> Circuit selection + stream attachment + preemptive launch
  circuitstats.c ----> Circuit Build Timeout (CBT) adaptive timing
  circuitmux.c ------> Per-channel circuit multiplexer
  circuitmux_ewma.c -> EWMA scheduling policy
  circuitpadding.c --> WTF-PAD state machines (Prop 254)
  crypt_path.c ------> Per-hop crypto state management

CHANNEL LAYER
  channel.c ---------> Abstract channel (state machine, identity lookup)
  channeltls.c ------> TLS channel implementation (wraps or_connection_t)
  channelpadding.c --> Link-level netflow padding

RELAY LAYER
  relay.c -----------> Cell forwarding + stream dispatch (3563 lines)
  relay_msg.c -------> Relay message encode/decode (v0 + v1 cell formats)
  command.c ---------> Cell command dispatch (CREATE/CREATED/RELAY/DESTROY)
  onion.c -----------> CREATE cell parsing + onion queue management

CONGESTION CONTROL
  congestion_control_common.c -> Shared CC logic, BDP estimation, RTT
  congestion_control_vegas.c --> Vegas algorithm (alpha/beta/gamma/delta)
  congestion_control_flow.c ---> XON/XOFF stream flow control
  sendme.c --------------------> SENDME cell generation + verification

CONFLUX (MULTI-PATH)
  conflux.c ---------> Circuit selection algorithm (MinRTT/LowRTT/CwndRTT)
  conflux_pool.c ----> Linked/unlinked circuit pool management
  conflux_cell.c ----> LINK/LINKED/SWITCH cell encoding
  conflux_params.c --> Consensus parameter management
  conflux_util.c ----> Stream list synchronization

CRYPTO
  onion_crypto.c ----> Handshake dispatch (FAST/ntor/ntor3)
  onion_ntor.c ------> Curve25519 ntor handshake
  onion_ntor_v3.c ---> ntor v3 with encrypted messages + param negotiation
  onion_fast.c ------> CREATE_FAST (deprecated, first-hop only)
  hs_ntor.c ---------> Hidden service ntor (INTRODUCE + RENDEZVOUS keys)
  relay_crypto.c ----> Relay cell encrypt/decrypt dispatch
  relay_crypto_tor1.c> Original AES-CTR + SHA1/SHA3 relay crypto
  relay_crypto_cgo.c > Counter-Galois-Onion wide-block relay crypto

DoS DEFENSE
  dos.c -------------> Per-IP rate limiting (connections, circuits, streams)

SCHEDULING
  scheduler.c -------> Scheduler coordination
  scheduler_kist.c --> KIST (kernel socket buffer awareness)
  scheduler_vanilla.c> Round-robin fallback

MAIN LOOP
  mainloop.c --------> Event loop + periodic timers + connection array
  connection.c ------> Master connection manager (5981 lines, 89 functions)
  cpuworker.c -------> Threadpool for onion handshakes
  periodic.c --------> Role-based periodic event system
  netstatus.c -------> Dormant/online state tracking
```

## Core Data Structures (Inheritance)

```
connection_t (base)
  |-- or_connection_t (relay-to-relay, TLS)
  |     |-- tls, handshake_state, identity_digest, link_proto
  |     |-- channel_tls_t *chan (backpointer to channel)
  |     |-- token_bucket_rw_t bucket (rate limiting)
  |
  |-- edge_connection_t (stream endpoints)
  |     |-- stream_id, on_circuit, cpath_layer
  |     |-- package_window, deliver_window (flow control)
  |     |-- XOFF/XON flow control state (drain_rate, ewma)
  |     |
  |     |-- entry_connection_t (client SOCKS)
  |           |-- socks_request, chosen_exit_name
  |           |-- isolation fields (session_group, nym_epoch, etc.)
  |           |-- pending_optimistic_data
  |
  |-- listener_connection_t (accept sockets)
        |-- dns_server_port, entry_cfg

circuit_t (base)
  |-- n_chan, n_circ_id (next hop)
  |-- package_window, deliver_window
  |-- congestion_control_t *ccontrol
  |-- conflux_t *conflux
  |-- circpad_machine_spec_t *padding_machine[]
  |
  |-- origin_circuit_t (client-originated)
  |     |-- cpath (linked list of crypt_path_t)
  |     |-- build_state (cpath_build_state_t)
  |     |-- p_streams (edge_connection_t list)
  |     |-- guard_state, path_state (path bias)
  |     |-- isolation fields (dest_port, client_addr, socks_username)
  |     |-- hs_ident (hidden service circuit identity)
  |
  |-- or_circuit_t (relay-side)
        |-- p_chan, p_circ_id (previous hop)
        |-- n_streams, resolving_streams
        |-- relay_crypto_t crypto
        |-- rend_splice (rendezvous partner circuit)
        |-- DoS token buckets (introduce2_bucket, stream_limiter)
```

## Circuit Lifecycle

```
1. LAUNCH
   circuit_launch() -> origin_circuit_init() -> choose path
     |-- choose_good_entry_server() via guard subsystem
     |-- choose_good_middle_server() bandwidth-weighted
     |-- choose_good_exit_server() by policy

2. BUILD (state machine)
   circuit_send_first_onion_skin()
     |-- channel_connect_for_circuit() -> get/create channel
     |-- onion_skin_create() -> ntor3 handshake
     |-- Send CREATE2 cell
   circuit_send_next_onion_skin() [on CREATED2 reply]
     |-- onion_skin_client_handshake() -> derive keys
     |-- cpath_init_circuit_crypto() -> init relay crypto
     |-- Send EXTEND2 for next hop (via RELAY_EARLY)
     |-- Repeat until 3 hops done

3. USE
   circuit_get_best() finds circuit matching purpose + isolation
   connection_ap_attach_chosen() attaches stream
   relay_send_command_from_edge_() sends RELAY_BEGIN

4. RELAY PROCESSING (per cell)
   command_process_relay_cell()
     |-- relay_decrypt_cell() -> peel/add onion layers
     |-- If recognized: process locally (stream data, SENDME, etc.)
     |-- If not recognized: forward to next hop
     |-- circuitmux decides output order (EWMA scheduling)

5. CLOSE
   circuit_mark_for_close() -> deferred to event loop
   circuit_about_to_free() -> cleanup streams, channels, crypto
   [NOT freed inline -- prevents UAF during event processing]
```

## Channel State Machine

```
CLOSED -> OPENING -> OPEN -> MAINT -> CLOSING -> CLOSED
                       |                  ^
                       +-> ERROR ---------+

Key operations on OPEN:
- channel_write_packed_cell() -> queue cell for sending
- channel_flush_some_cells() -> dequeue from circuitmux
- channel_process_cell() -> dispatch to command handler

On channel death:
- channel_close_for_error() or channel_close_from_lower_layer()
- circuit_unlink_all_from_channel() -> mark ALL circuits for close
  (THIS is why Tor never has stale circuits on dead connections)
```

## Connection Manager (5981 lines)

```
connection_new() -> allocate by type
connection_add_impl() -> register in global array + libevent
connection_handle_read() -> TLS recv -> buffer -> process_inbuf()
connection_handle_write() -> buffer -> TLS send -> rate limit
connection_mark_for_close() -> add to closeable list
close_closeable_connections() -> actually free (event loop epilogue)

Rate limiting:
- Per-connection token buckets (read + write)
- Global token bucket (all traffic)
- Global relayed token bucket
- Refill every second

Out-of-sockets handling:
- pick_oos_victims() -> select connections to kill
- oos_victim_comparator() -> prefer OR connections, older, fewer circuits
```

## Relay Cell Processing

```
relay.c:circuit_receive_relay_cell()
  |
  |-- relay_decrypt_cell() dispatches to:
  |     |-- tor1: AES-CTR decrypt + SHA1/SHA3 digest check
  |     |-- CGO: UIV+ wide-block decrypt + nonce recognition
  |
  |-- If recognized (for us):
  |     |-- Parse relay header (command, stream_id, length)
  |     |-- Dispatch by command:
  |           RELAY_BEGIN -> open exit connection
  |           RELAY_DATA -> forward to stream
  |           RELAY_END -> close stream
  |           RELAY_CONNECTED -> notify AP connection
  |           RELAY_SENDME -> refill window
  |           RELAY_EXTEND -> circuit_extend()
  |           RELAY_EXTENDED -> complete hop, advance cpath
  |           RELAY_RESOLVE -> DNS resolution
  |           RELAY_RESOLVED -> return DNS result
  |           RELAY_BEGIN_DIR -> open directory stream
  |           XOFF/XON -> stream flow control
  |
  |-- If not recognized:
        circuit_package_relay_cell() -> forward to next/prev hop

relay.c:circuit_package_relay_cell()
  |-- relay_encrypt_cell_outbound/inbound()
  |-- Enqueue on circuit's cell queue
  |-- circuitmux activates circuit on channel
  |-- Scheduler flushes cells to kernel
```

## Crypto Hierarchy

```
LINK LAYER:
  TLS 1.2/1.3 (via channeltls.c)
  |-- X.509 certificates for identity
  |-- v3 handshake: VERSIONS + CERTS + AUTH_CHALLENGE + AUTHENTICATE
  |-- Result: encrypted bidirectional channel

CIRCUIT LAYER (per hop):
  ntor v3 handshake (onion_ntor_v3.c)
  |-- Client: generate ephemeral X25519
  |-- Server: DH(y,X) + DH(b,X) -> HKDF -> keys
  |-- Encrypted parameter negotiation (CC, relay crypto algo)
  |-- Result: forward_key + backward_key per hop

  Relay crypto options:
  |-- TOR1: AES-128-CTR + SHA1 (legacy)
  |-- TOR1_HS: AES-128-CTR + SHA3-256 (hidden services)
  |-- CGO: UIV+ wide-block cipher (AES + Polyval)
  |         |-- 509-byte blocks, nonce-based recognition
  |         |-- Key ratcheting after each recognized cell

HIDDEN SERVICE LAYER:
  hs_ntor (hs_ntor.c)
  |-- INTRODUCE1: DH with intro key -> enc/MAC keys
  |-- RENDEZVOUS1: two DH ops -> MAC + key_seed
  |-- Circuit key expansion via SHAKE-256
```

## Congestion Control (Vegas)

```
congestion_control_vegas_process_sendme():
  |
  |-- Measure RTT from SENDME timestamps
  |-- Compute BDP = cwnd * min_rtt / srtt
  |-- Compute queue = cwnd - BDP
  |
  |-- SLOW START (in_slow_start == true):
  |     cwnd += sendme_inc (per SENDME)
  |     Exit if: queue > gamma OR RTT inflation > 25%
  |     Limited slow start: increment = max(1, sendme_inc * ss_cap / cwnd)
  |
  |-- STEADY STATE:
  |     if cwnd_full:
  |       queue < alpha -> cwnd += delta   (underutilized)
  |       queue > beta  -> cwnd -= delta   (congested)
  |       else          -> hold            (optimal)
  |
  |-- Path-dependent parameters:
  |     SBWS: alpha=478, beta=1218, gamma=738, delta=1968
  |     Exit: alpha=984, beta=1316, gamma=984, delta=1640
  |     Onion: alpha=984, beta=1968, gamma=1312, delta=2296

XON/XOFF flow control (per-stream):
  |-- XOFF: pause stream when buffer > threshold
  |-- XON: resume when drain_rate changes significantly
  |-- EWMA drain rate tracking for adaptive XON
```

## Scheduler (KIST)

```
KIST algorithm:
1. For each pending channel:
   - Query kernel: TCP_INFO (cwnd, unacked, mss)
   - Query kernel: SIOCOUTQNSD (notsent bytes)
   - Compute: write_limit = cwnd*mss - notsent - outbuf
2. For each channel with write_limit > 0:
   - circuitmux_get_first_active_circuit() [EWMA-weighted]
   - Flush up to write_limit cells
3. Repeat every KIST_SCHED_RUN_INTERVAL_DEFAULT ms

Fallback (vanilla): Round-robin, flush up to 1000 cells per channel
```

## DoS Mitigation

```
dos.c tracks per-IP:
- Connection rate (token bucket)
- Circuit creation rate (token bucket, default 3/sec burst 90)
- Stream creation rate
- INTRODUCE2 rate (per intro point)

Defense actions (graduated):
- NONE: allow
- CLOSE: close connection
- REFUSE: send back error
- Per-circuit queue limits (2500 cells default)
```

## Periodic Events

```
Role-based events (fire only when role active):
  CLIENT: fetch consensus, predict+launch circuits, check DNS
  RELAY: heartbeat, padding stats, rotate certs, save state
  DIRAUTH: generate consensus, assign flags
  HS_SERVICE: publish descriptors, rotate intro points
  ALL: add entropy, clean caches, prune routers

Key intervals:
  1 second: second_elapsed_callback (online check)
  10 seconds: KIST scheduler tick
  30 seconds: prune old routers
  60 seconds: clean caches, check consensus expiry
  300 seconds: heartbeat log, save state
  3600 seconds: rotate X.509 cert, bandwidth authority
```

## SOCKS5 Protocol Flow

```
1. GREETING: Client -> [0x05, NMETHODS, METHODS...]
             Server <- [0x05, CHOSEN_METHOD]

2. AUTH (if method 0x02):
             Client -> [0x01, ULEN, USER, PLEN, PASS]
             Server <- [0x01, 0x00]  (success)

3. REQUEST:  Client -> [0x05, CMD, 0x00, ATYP, ADDR, PORT]
             (CMD: 0x01=CONNECT, 0xF0=RESOLVE, 0xF1=RESOLVE_PTR)
             (ATYP: 0x01=IPv4, 0x03=hostname, 0x04=IPv6)

4. REPLY:    Server <- [0x05, STATUS, 0x00, ATYP, ADDR, PORT]

Special: Tor extended params via username "<torS0X>0"
Isolation: IsolateSOCKSAuth uses username:password for circuit isolation
```

## Key Design Patterns MOOR Should Follow

1. **Deferred close**: `circuit_mark_for_close()` never frees inline. Actual free happens in event loop epilogue via `close_closeable_connections()`. Prevents UAF.

2. **Channel death = immediate circuit cleanup**: `circuit_unlink_all_from_channel()` synchronously marks ALL circuits for close when a channel dies. No stale circuits ever.

3. **No absolute per-IP limits**: Only rate-based token buckets. Counters that only go up are bugs.

4. **Separation of concerns**: channel (transport) vs circuit (routing) vs stream (application). Each layer has its own lifecycle, state machine, and cleanup.

5. **Consensus-driven parameters**: All tuning (CC params, DoS thresholds, padding timers, queue limits) comes from consensus. No hardcoded magic numbers in the hot path.

6. **CPU-intensive work offloaded**: Onion handshakes go to worker threadpool. Event loop never blocks on crypto.

7. **Graceful degradation**: Out-of-sockets handler kills connections by priority. OOM handler kills circuits by queue depth. Hibernation stops accepting new circuits before killing existing ones.

8. **Path bias as defense**: Track build success rate AND stream-use success rate per guard. Disable guards that fail too often.

---

# Tor Feature Modules (src/feature/) — 110K lines

## Guard Selection (feature/client/entrynodes.c — 4353 lines)

```
SAMPLED SET (persisted, max 60 or 20% of network)
  |-- Expanded from consensus as guards appear
  |-- Expired after 120 days (unconfirmed) or 20 days (unlisted)
  |
  v
FILTERED SET (runtime, config-dependent)
  |-- Passes ExcludeNodes, firewall, path-bias checks
  |
  v
USABLE FILTERED SET
  |-- Filtered AND recently reachable
  |
  v
CONFIRMED GUARDS (persisted, ordered by sampled_idx)
  |-- Promoted from sampled on first successful circuit
  |-- Sorted by Prop 310 sampling order
  |
  v
PRIMARY GUARDS (runtime, max 3)
  |-- Top 3 from confirmed (filtered, reachable)
  |-- Fallback to unconfirmed sampled if needed

Circuit guard selection:
  1. Try primary guards (immediate)
  2. If all primary down: try confirmed (with retry schedule)
  3. If all confirmed down: try first sampled filtered
  4. Pending circuits upgraded if primary recovers

Retry schedule (time since first failure):
  0-6h:   primary 10min, non-primary 60min
  6h-4d:  primary 90min, non-primary 4h
  4d-7d:  primary 4h, non-primary 18h
  7d+:    primary 9h, non-primary 36h

State persisted to disk (text key=value):
  in, rsa_id, sampled_on, sampled_idx, confirmed_on, confirmed_idx,
  pb_circ_attempts, pb_circ_successes, pb_use_attempts, pb_use_successes
```

## Path Bias Detection (feature/client/circpathbias.c — 1669 lines)

```
BUILD TRACKING:
  pathbias_count_build_attempt() — after 2nd hop AWAITING_KEYS
  pathbias_count_build_success() — circuit fully built
  
  Thresholds (configurable):
    Notice: 70% build rate
    Warn:   50% build rate  
    Disable: 30% build rate (guard dropped)
    Min circuits before judging: 150

STREAM TRACKING:
  pathbias_count_use_attempt() — stream opened on circuit
  pathbias_mark_use_success() — RELAY_CONNECTED received
  pathbias_send_usable_probe() — probe with RELAY_PADDING if suspicious
  
  Thresholds:
    Disable: 60% stream success rate
    
States: NEW_CIRC → BUILD_ATTEMPTED → BUILD_SUCCEEDED →
        USE_ATTEMPTED → USE_SUCCEEDED → ALREADY_COUNTED
```

## Pluggable Transports (feature/client/transports.c — 2291 lines)

```
Managed PT Protocol (Prop 180):
  1. Tor spawns external process with TOR_PT_* environment
  2. PT outputs: VERSION, CMETHOD/SMETHOD lines, METHODS DONE
  3. Tor registers transports for circuit building
  4. On SIGHUP: mark-and-sweep (re-read config, destroy obsolete)

Transport lifecycle:
  transport_new() → transport_add() → mark → sweep → transport_free()

PT process I/O:
  stdout → parse VERSION/METHOD/STATUS lines
  stderr → log messages
  exit → cleanup and re-launch if needed
```

## Hidden Service Server (feature/hs/hs_service.c — 4743 lines)

```
DESCRIPTOR PUBLISH FLOW:
  1. build_service_desc_plaintext() — version, lifetime, signing cert
  2. build_service_desc_superencrypted() — blinded key, auth clients
  3. build_service_desc_encrypted() — intro points, PoW params
  4. service_encode_descriptor() — base64 + sign
  5. upload_descriptor_to_all() — 2 replicas × 2 time periods → HSDirs

INTRO POINT MANAGEMENT:
  pick_needed_intro_points() — select relay nodes
  launch_intro_point_circuits() — 3-hop with vanguards
  service_intro_circ_has_opened() — send ESTABLISH_INTRO
  cleanup_intro_points() — expire after ~24h

RENDEZVOUS HANDLING:
  service_handle_introduce2() — decrypt client intro, extract RP
  service_rendezvous_circ_has_opened() — complete e2e handshake

DESCRIPTOR ENCRYPTION (two layers):
  Superencrypted: AES-256-CTR + SHA3 MAC, key from blinded_pk
  Encrypted: AES-256-CTR + SHA3 MAC, key from client auth
  Per-client auth: X25519 DH → per-client descriptor cookie

ROTATION:
  run_housekeeping_event() — every 10 seconds
  rotate_service_descriptors() — current → next at time period boundary
  rotate_pow_seeds() — PoW seed rotation for DoS defense
```

## Hidden Service Client (feature/hs/hs_client.c — 2803 lines)

```
CONNECTION FLOW:
  1. hs_client_launch_v3_desc_fetch() — fetch from HSDir (PIR optional)
  2. client_desc_has_arrived() — decrypt descriptor
  3. client_get_random_intro() — pick usable intro point
  4. hs_client_send_introduce1() — encrypted intro to intro relay
  5. handle_introduce_ack() — ACK from intro relay
  6. client_rendezvous_circ_has_opened() — RP ready
  7. handle_rendezvous2() — e2e key exchange complete, stream ready

CLIENT AUTHORIZATION:
  hs_client_register_auth_credentials() — store per-service key
  find_client_auth() — lookup auth key for service
  Credentials: X25519 keypair → decrypt descriptor cookie
```

## Directory Authority Voting (feature/dirauth/dirvote.c — 4936 lines)

```
5-PHASE VOTING PROTOCOL:

Phase 1 — VOTING_STARTS:
  Each DA generates vote (relay list + flags + bandwidth)
  POST vote to all other DAs

Phase 2 — FETCH_MISSING_VOTES:
  Request any missing votes from other DAs

Phase 3 — VOTING_ENDS:
  networkstatus_compute_consensus():
    - Select consensus method (highest supported by quorum)
    - Compute median times (valid-after, fresh-until, valid-until)
    - For each relay in ANY vote:
        compute_routerstatus_consensus() — aggregate flags, bandwidth
        get_all_possible_sybil() — detect IP-based sybil
    - Compute bandwidth weights (Wgg, Wee, Wmg, etc.)
    - Sign with identity key

Phase 4 — FETCH_MISSING_SIGNATURES:
  Request signatures from other DAs until threshold met

Phase 5 — INTERVAL_STARTS:
  Publish consensus to directory mirrors + clients

SYBIL DETECTION:
  get_sybil_list_by_ip_version() — group relays by /16 subnet
  get_all_possible_sybil() — union IPv4 + IPv6 sybil sets
  Sybil relays get BadExit flag
```

## Shared Random Value (feature/dirauth/shared_random.c — 1294 lines)

```
COMMIT-REVEAL PROTOCOL (Prop 250):

COMMIT PHASE:
  Each DA: generate random RN, publish H(H(RN) || TIMESTAMP)
  
REVEAL PHASE:
  Each DA: publish (RN, TIMESTAMP)
  Verify: H(revealed) matches committed hash

SRV COMPUTATION:
  SRV = SHA3("shared-random" || num_reveals || version || prev_srv ||
              sorted(all_revealed_RNs))

Used for: HSDir index randomization, relay ordering
Disaster SRV: deterministic fallback if consensus unavailable
```

## Relay Descriptor Generation (feature/relay/router.c — 3729 lines)

```
DESCRIPTOR FIELDS:
  router <nickname> <address> <or_port> <dir_port>
  identity-ed25519 <cert>
  or-address [ipv6]:port
  platform <version>
  proto <protocol-list>
  published <ISO_TIME>
  fingerprint <RSA_FP>
  uptime <seconds>
  bandwidth <rate> <burst> <capacity>
  onion-key <RSA_KEY>
  signing-key <RSA_KEY>
  ntor-onion-key <CURVE25519_KEY>
  ntor-onion-key-crosscert <CROSSCERT>
  family <relay_list>
  exit-policy accept/reject <rules>
  router-sig-ed25519 <ED25519_SIG>
  router-signature <RSA_SIG>

REGENERATION TRIGGERS:
  - Config change
  - Bandwidth change (>= 50% or significant)
  - IP address change
  - Onion key rotation (every 7 days)
  - 18-hour forced republish
```

## Exit DNS (feature/relay/dns.c — 2326 lines)

```
DNS HIJACK DETECTION:
  dns_launch_correctness_checks():
    1. Query known-good hostnames (should resolve)
    2. Query known-bad hostnames (should NOT resolve)
    3. If bad hostnames resolve → DNS hijacking detected
    4. Set dns_is_completely_invalid flag
    5. Refuse to serve as exit until DNS clean

DNS CACHE:
  cached_resolve_t: address → IPv4/IPv6 result + TTL
  RESOLVED_CLIPPED_TTL = 60s (prevent DNS oracle attacks)
  Negative caching (NXDOMAIN results cached)
```

## Relay Metrics (feature/relay/relay_metrics.c — 1338 lines)

```
PROMETHEUS-COMPATIBLE METRICS:
  OOM bytes, onionskins processed, socket count,
  DNS queries/errors, TCP exhaustion, connections,
  streams, congestion control, DoS counters,
  traffic bytes, relay flags, circuits,
  signing cert expiry, EST_REND/EST_INTRO/INTRO1/REND1 actions

Per-action tracking with enums:
  EST_INTRO: success, malformed, unsuitable_circuit, dead
  EST_REND: success, unsuitable, single_hop, malformed, dup_cookie, dead
  INTRO1: success, dead, malformed, unknown_service, rate_limited, reused, single_hop
  REND1: success, unsuitable, malformed, unknown_cookie, dead
```

## Flag Computation (feature/dirauth/voteflags.c — 690 lines)

```
FLAG ASSIGNMENT ALGORITHM:
  Fast:   bandwidth >= 12.5th percentile (floor: 4 KB/s)
  Stable: uptime >= median
  Guard:  Fast + Stable + bw >= median non-exit + known >= 8 days
  HSDir:  Fast + Stable + uptime >= 96 hours
  Exit:   self-declared (DA always preserves)
  BadExit: manually flagged or detected sybil
```

## Hibernation (feature/hibernate/hibernate.c — 1277 lines)

```
STATES: AWAKE → SOFT_LIMIT → HARD_LIMIT → DORMANT

SOFT_LIMIT: Stop accepting new circuits, allow existing
HARD_LIMIT: Close all connections
DORMANT: No network activity, wait for accounting period reset

Accounting: track bytes read/written per period
Wake scheduling: calculate when bandwidth allowance resets
```

## Consensus Diffing (feature/dircommon/consdiff.c — 1420 lines)

```
ED-STYLE LINE DIFFS:
  consdiff_gen_diff() — generate diff between two consensus docs
  consdiff_apply_diff() — apply diff to produce new consensus
  
  Optimized: sorts by router identity for near-linear time
  Format: standard ed commands (a=append, d=delete, c=change)
  
  consdiffmgr.c manages cached diffs with:
    - Worker thread for background diff generation
    - Worker thread for background compression
    - Multiple compression methods (zlib, zstd, lzma)
    - Cache eviction by staleness
```

## Control Port (feature/control/ — 10K lines)

```
COMMANDS (control_cmd.c):
  AUTHENTICATE, AUTHCHALLENGE, PROTOCOLINFO
  GETINFO, GETCONF, SETCONF, RESETCONF, LOADCONF, SAVECONF
  SIGNAL (RELOAD, SHUTDOWN, DUMP, DEBUG, HALT, NEWNYM, CLEARDNSCACHE, HEARTBEAT)
  EXTENDCIRCUIT, SETCIRCUITPURPOSE, ATTACHSTREAM, REDIRECTSTREAM
  CLOSESTREAM, CLOSECIRCUIT
  MAPADDRESS, RESOLVE
  USEFEATURE, DROPGUARDS, DROPTIMEOUTS
  HSFETCH, HSPOST, ADD_ONION, DEL_ONION
  ONION_CLIENT_AUTH_ADD/REMOVE/VIEW
  TAKEOWNERSHIP, DROPOWNERSHIP

EVENTS (control_events.c):
  CIRC, STREAM, ORCONN, BW, DEBUG, INFO, NOTICE, WARN, ERR
  NEWDESC, ADDRMAP, DESCCHANGED, NS, STATUS_GENERAL/CLIENT/SERVER
  GUARD, NETWORK_LIVENESS, CIRC_MINOR, TRANSPORT_LAUNCHED
  HS_DESC, HS_DESC_CONTENT, CONN_BW, CIRC_BW, CELL_STATS, CONF_CHANGED

AUTH METHODS (control_auth.c):
  Cookie: 32-byte file, hex-encoded in AUTHENTICATE
  HashedControlPassword: S2K hashed password
  SafeCookie: HMAC-SHA256 challenge-response (prevents eavesdropping)

GETINFO KEYS (control_getinfo.c — 100+ handlers):
  version, config-text, config-file, exit-policy/*
  circuit-status, stream-status, orconn-status
  address, traffic/read, traffic/written
  process/pid, uptime, network-liveness
  consensus/*, ns/*, md/*, desc/*
  ip-to-country/*, accounting/*
  sr/current, sr/previous
  downloads/*, status/bootstrap-phase
```

## Node List (feature/nodelist/ — 15K lines)

```
nodelist.c: "Live" network view combining routerinfo + routerstatus + microdesc
  node_t = { routerinfo_t, routerstatus_t, microdesc_t }
  
  Indexed by: RSA digest, Ed25519 key
  Filtered by: flags, protocols, address family, exit policy
  
networkstatus.c: Consensus management
  Download, parse, validate, cache consensus
  Track freshness (valid-after, fresh-until, valid-until)
  Compute path fraction needed for circuits

routerlist.c: Router descriptor storage
  Add/remove/replace descriptors
  Download scheduling with retry
  Old descriptor cleanup
  
node_select.c: Bandwidth-weighted node selection
  smartlist_choose_node_by_bandwidth_weights()
  Wgg/Wee/Wmg/Wme weight application
  ExcludeNodes/EntryNodes/ExitNodes enforcement
```

## Statistics (feature/stats/ — 6K lines)

```
rephist.c: Reputation history
  MTBF tracking per relay (mean time between failures)
  Weighted fractional uptime
  Exit stream/bandwidth statistics
  DNS error tracking
  Overload/TCP exhaustion counters

geoip_stats.c: Geographic statistics
  Per-country client counts (for bridge stats)
  Directory request tracking by country
  Transport usage statistics

predict_ports.c: Port prediction
  Track which ports client uses
  Preemptively build exit circuits for predicted ports
  Decay old predictions

bwhist.c: Bandwidth history
  15-minute interval bandwidth tracking
  Read/written/dir-read/dir-written
  Persisted across restarts
```

## Key Design Patterns from Feature Modules

9. **5-phase voting with consensus methods**: DAs don't just collect signatures — they run a full Byzantine protocol with method versioning for forward compatibility.

10. **Dual-layer HS descriptor encryption**: Superencrypted (anyone with address can fetch) + encrypted (only authorized clients can read). Per-client auth via X25519 DH.

11. **Managed PT protocol**: External process communication via stdout/stderr with environment-based configuration. Mark-and-sweep lifecycle on config reload.

12. **Download retry with exponential backoff**: dlstatus.c implements randomized exponential backoff for all directory downloads. Separate schedules for consensus vs descriptors vs bridges.

13. **Consensus diffing**: ED-style line diffs with background worker threads for generation and compression. Multiple compression methods. Reduces bandwidth by 90%+.

14. **Reputation tracking**: MTBF, weighted fractional uptime, exit stream stats, DNS error rates. Used for flag assignment and relay selection.

15. **Hibernation as graduated defense**: AWAKE → SOFT_LIMIT (no new circuits) → HARD_LIMIT (close all) → DORMANT (no network). Bandwidth accounting per period with scheduled wakeup.

16. **DNS hijack detection**: Exit relays test known-good and known-bad hostnames. If bad hostnames resolve, DNS is compromised — refuse to serve as exit.
