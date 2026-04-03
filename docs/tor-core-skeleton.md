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
