# Architecture

## Overview

MOOR is a single C binary that runs in one of several modes: **client**,
**relay**, **directory authority (DA)**, **hidden service (HS)**,
**OnionBalance**, **bridge**, **bridge authority**, or **bridgedb**. Every mode
shares the same crypto, cell, connection, and event-loop infrastructure.

The binary links against libsodium, zlib, libevent, and pthreads — nothing
else. The post-quantum primitives (ML-KEM-768, ML-DSA-65, Falcon-512) are
vendored from PQClean reference implementations in `src/pqclean/` and built
in-tree. No OpenSSL. No GnuTLS. No liboqs.

Source size: roughly **55 000 lines of C** across `src/` and `include/moor/`,
plus roughly **18 000 lines** of vendored NIST PQ reference code in
`src/pqclean/`.

## Source layout

```
src/
  main.c              Entry point, CLI/config parsing, mode dispatch, event loop setup,
                      scanner-honeypot ingress on non-bridge relays
  log.c               Leveled logging (DEBUG/INFO/WARN/ERROR/FATAL) with timestamps
  crypto.c            Ed25519 sign/verify, X25519 DH, ChaCha20 / ChaCha20-Poly1305 /
                      XChaCha20-Poly1305 AEAD, BLAKE2b, HKDF, key blinding, Ed->Curve
  kem.c               ML-KEM-768 KEM wrapper: keygen, encapsulate, decapsulate
  sig.c               ML-DSA-65 wrapper: keygen, sign, verify (consensus co-signing)
  falcon.c            Falcon-512 wrapper: keygen, sign, verify (HS descriptors + INTRODUCE1)
  cell.c              Fixed 514-byte cell pack/unpack, relay payload pack/unpack,
                      CREATE / CREATED / DESTROY builders, rolling BLAKE2b digest
  connection.c        TCP listener, connection pool, Noise_IK link handshake + ML-KEM-768
                      post-handshake encapsulation, AEAD cell send/recv, transport-aware
                      I/O, non-blocking sockets, dual-stack IPv4/IPv6
  circuit.c           Circuit pool, CREATE_PQ / EXTEND_PQ handlers (X25519 + ML-KEM-768),
                      path selection (bandwidth-weighted, GeoIP-diverse, Prop 271 guards),
                      vanguards (L2/L3), Vegas congestion control (Prop 324/329), CBT,
                      path-bias detection, OOM watchdog, async event-driven builder,
                      self-loop filter (refuses to route through own address)
  relay.c             Relay cell processing, CREATE / EXTEND handlers, exit connections,
                      exit policy enforcement, SSRF protection, async EXTEND worker,
                      relay registration, DNS cache integration
  node.c              Descriptor create / serialize / sign, consensus parse / serialize,
                      relay selection helpers
  directory.c         DA consensus building, vote exchange, encrypted DA-to-DA channel
                      (ephemeral X25519 DH + AEAD), relay registration, Ed25519 +
                      ML-DSA-65 dual signing, GeoIP flag assignment, build-ID gate
  socks5.c            SOCKS5 proxy server, per-domain circuit isolation, pre-built
                      circuit pool, queued BUILDING state for clearnet + HS, conflux
                      integration, .onion ingress is rejected
  hidden_service.c    HS keygen (Ed25519 + ML-KEM-768 + Falcon-512), key blinding
                      (time-period rotation), intro-point establishment (with vanguards),
                      descriptor encryption + Ed25519 / Falcon-512 dual signing,
                      rendezvous protocol, PQ-committed .moor addresses
                      (base32(Ed25519_pk(32) || BLAKE2b_16(ML-KEM_pk || Falcon_pk))),
                      revision-counter wall-clock floor
  dht.c               Distributed hash table for HS descriptors: ring position
                      (BLAKE2b), XOR distance, 3 replicas per epoch, PIR fetch
                      (2-server XOR PIR and DPF-PIR pair queries)
  config.c            Config-file parser (Tor-compatible "Key Value" syntax), exit
                      policy parser, external IP auto-detection, DA address list
                      with snapshot/restore
  event.c             Event loop: epoll on Linux, select/poll elsewhere, with timers
  transport.c         Pluggable transport registry
  transport_scramble.c ASCII HTTP prefix + ChaCha20 stream framing
  transport_shade.c   Elligator2-inspired key obfuscation + ChaCha20-Poly1305 AEAD +
                      inter-arrival-time modes
  transport_mirage.c  TLS 1.3 camouflage with real X25519 DH and configurable SNI
  transport_shitstorm.c Chrome 146 JA4 fingerprint + Elligator2 + ECH GREASE + HTTP/2
  transport_speakeasy.c SSH-2.0 banner + KEX + encrypted channel framing
  transport_nether.c  Minecraft 1.21.4 handshake + login + plugin-channel framing
  geoip.c             Tor-compatible GeoIP database parser (IPv4/IPv6): country +
                      AS lookup by binary search
  fragment.c          Cell fragmentation for oversized payloads (KEM ciphertexts):
                      fragment ID, sequence numbers, reassembly state machine
  pow.c               Argon2id proof-of-work for relay admission DoS protection,
                      nonce replay cache, configurable difficulty + memory
  wfpad.c             WTF-PAD adaptive padding: Markov state machines (web / stream /
                      generic), FRONT Rayleigh-sampled front padding, volume padding
                      (power-of-two), constant-rate base layer
  mix.c               Poisson mixing pool (exponential delay, cover cells)
  conflux.c           Multi-path bonding (up to 4 legs), Feistel PRP sequence encoding,
                      reorder buffer, SKIPS RTT-adaptive scheduling
  bw_auth.c           Bandwidth authority: relay measurement, effective bandwidth
                      (self-reported capped at 1.2x measured)
  ratelimit.c         Per-IP token bucket rate limiting across connection, circuit,
                      intro, establish, and rendezvous events
  scheduler.c         Per-circuit EWMA output queues, round-robin scheduling
  monitor.c           Runtime stats, Tor-compatible control port (AUTHENTICATE,
                      GETINFO, SETEVENTS, SIGNAL NEWNYM / SHUTDOWN)
  dns_cache.c         Exit-side DNS cache with TTL expiry
  dns_server.c        DNS-over-TCP recursive resolver intended for HS exposure
  bootstrap.c         Bootstrap progress reporting ("Bootstrapped N%: phase")
  transparent.c       TransPort (iptables REDIRECT + SO_ORIGINAL_DST) + DNSPort
                      transparent proxying
  addressmap.c        Virtual .moor hostname → 127.192.0.0/10 mapping for TransPort
  onionbalance.c      Aggregate intro points from multiple HS backends under one
                      .moor address
  bridgedb.c          Bridge distribution service: deterministic per-client assignment
                      (keyed BLAKE2b)
  bridge_auth.c       Bridge authority: registration + descriptor storage
  exit_sla.c          Per-exit success-rate / latency tracking + scoring
  channel.c           Channel abstraction: multiplexed circuit transport over one
                      connection, state machine, mark-for-close
  sandbox.c           seccomp-bpf sandbox: syscall allow-list, no_new_privs, rlimits
  elligator2.c        Elligator2 point encoding for key obfuscation in transports
  exit_notice.c       Mandatory HTTP notice on :80 for every exit relay
  build_id.c          16-byte git-hash build ID stamped on every descriptor; DAs
                      reject descriptors whose build_id differs from theirs
  cJSON.c             Vendored cJSON (monitor / bridgedb minimal JSON)

  pqclean/            Vendored NIST PQ reference implementations (ML-KEM-768,
                      ML-DSA-65, Falcon-512, FIPS 202 SHA-3/SHAKE, FIPS 180 SHA-2, AES)

include/moor/
  moor.h              Master header: version, identity/key length constants, node flags,
                      mode enum, padding/BW/conflux/vanguard constants
  limits.h            Every capacity/timing/protocol limit in one file
  cell.h              Cell / relay commands, destroy + end reason codes, payload structs
  [module].h          Per-module public API and struct definitions
```

## How browsing through MOOR works (step by step)

This section walks through what happens when you point a browser at MOOR's
SOCKS5 port and visit a website.

### Step 0: Starting up

When you launch `moor` with no arguments, it starts in client mode and listens
for SOCKS5 connections on port 9050 (same as Tor). It also spawns a timer-driven
async builder that pre-builds circuits so they are ready when you need them.

During startup, the client:

1. Initializes libsodium.
2. Generates or loads an Ed25519 identity keypair.
3. Connects to a directory authority (DA) and downloads the **consensus** —
   a signed list of all relays in the network, their addresses, identity and
   ML-KEM public keys, bandwidth, flags, and country codes.
4. Verifies the consensus carries valid Ed25519 **and** ML-DSA-65 signatures
   from a majority of DAs. Both signatures must verify (sequential-AND).
5. Begins pre-building 3-hop circuits in the background.

Tor-style progress is printed:

```
Bootstrapped 10%: Connecting to a relay
Bootstrapped 25%: Performing link handshake
Bootstrapped 40%: Requesting network consensus
Bootstrapped 70%: Establishing a circuit
Bootstrapped 100%: Done
```

### Step 1: Your browser connects to MOOR

Your browser is configured to use `127.0.0.1:9050` as a SOCKS5 proxy. When you
visit `https://example.com`, the browser opens a TCP connection to MOOR and
sends a SOCKS5 CONNECT saying "please connect me to example.com:443".

MOOR's SOCKS5 server (`socks5.c`) accepts the request and applies per-domain
**circuit isolation** so different destinations never share a circuit.
Requests for `.onion` addresses are rejected at ingress — MOOR uses `.moor`.
If a matching circuit is not already cached, a pre-built circuit is pulled
from the pool.

### Step 2: Establishing a link to the guard relay

Before any circuit can be built the client needs an encrypted TCP connection
to the first relay (the **guard**). The link uses the **Noise_IK** pattern —
a formally-analyzed, authenticated key exchange:

```
Client already knows guard's Ed25519 public key (from the consensus).

  Client -> Guard:  ephemeral_pk(32) + encrypted(client_static_pk)(48)    [80 bytes]
  Guard  -> Client: ephemeral_pk(32) + encrypted(empty+MAC)(16)           [48 bytes]
```

After Noise_IK, both sides have symmetric send/recv keys derived from three
X25519 DH operations. These keys are only secure against classical computers.

To defend against quantum adversaries MOOR immediately performs an
**ML-KEM-768** encapsulation over the now-encrypted link:

```
  Client -> Guard:  ml_kem_pk (1184 bytes, encrypted)
  Guard  -> Client: ml_kem_ct (1088 bytes, encrypted)
```

Both sides decapsulate and mix the KEM shared secret into the existing link
keys via HKDF-BLAKE2b. The link is now resistant to both classical and quantum
adversaries. Link-layer rekey runs on an implicit counter trigger — there is no
handshake bit to negotiate PQ on or off.

Every cell sent over this link is encrypted with **ChaCha20-Poly1305 AEAD**
(16-byte tag). On the wire a cell is 532 bytes: 2-byte length prefix + 514-byte
cell plaintext + 16-byte AEAD tag.

### Step 3: Building a 3-hop circuit

With the encrypted link to the guard established the client builds a circuit
through **guard → middle → exit**:

- **Guard**: selected from relays with the Guard flag, bandwidth-weighted.
  The client pins its guard for 120 days (Prop 271 sampled/primary/confirmed
  sets activate once the network has ≥20 relays). If GeoIP is loaded, the
  guard is chosen from a different country / AS than the other hops.
- **Middle**: any Running relay, excluding the guard, same family, and same
  country / AS as guard or exit.
- **Exit**: a relay with the Exit flag whose exit policy allows the
  destination port.

The client's own address is filtered from every hop (self-loop filter), so a
dev / shared-NAT box cannot accidentally route a circuit through itself.

**Hop 1 (to guard).** The client sends a `CREATE_PQ` cell containing its
X25519 ephemeral public key and the relay's identity key (for binding). The
guard performs two X25519 DH operations — ephemeral/ephemeral (forward
secrecy) and ephemeral/onion (the onion key is a Curve25519 key that rotates
every 28 days, separate from the permanent identity key). The guard derives
circuit keys via HKDF (identity_pk in the salt) and replies with `CREATED_PQ`.
An ML-KEM-768 encapsulation then follows over fragmented `CELL_KEM_CT` cells,
and the KEM shared secret is mixed into the circuit keys. The client now has
forward / backward ChaCha20 stream-cipher keys for hop 1.

**Hop 2 (to middle).** The client wraps a `RELAY_EXTEND_PQ` command in a
relay cell, encrypts it with hop 1's key, and sends it. The guard decrypts
one layer, sees the extend, and opens a TCP connection to the middle relay
(reusing an existing one if available) with its own Noise_IK + ML-KEM-768
link handshake. The guard forwards `CREATE_PQ` to the middle, receives
`CREATED_PQ`, and sends `RELAY_EXTENDED_PQ` back to the client. The client
now has circuit keys for hop 2. The guard cannot read hop 2's encrypted content.

**Hop 3 (to exit).** Same as hop 2, but the extend traverses guard and
middle to reach the exit. The client holds three sets of symmetric keys, one
per hop.

```
Client --- [hop 1 keys] --- Guard --- [hop 2 keys] --- Middle --- [hop 3 keys] --- Exit
```

### Step 4: Sending your web request

The client sends a `RELAY_BEGIN` cell telling the exit to connect to
`example.com:443`. The payload travels through three layers of encryption:

```
Plaintext: RELAY_BEGIN "example.com:443"
  -> encrypt with hop 3 key (exit)
  -> encrypt with hop 2 key (middle)
  -> encrypt with hop 1 key (guard)
  = fully encrypted cell on the wire
```

The guard decrypts one layer and forwards to the middle. The middle decrypts
one layer and forwards to the exit. The exit decrypts the final layer, sees
the `RELAY_BEGIN`, and opens a TCP connection to example.com:443. It replies
`RELAY_CONNECTED`.

Your browser's TLS handshake then flows as `RELAY_DATA` cells through the
circuit. Each cell carries up to 498 bytes of user data (509-byte payload
minus 11-byte relay header).

### Step 5: Data flows back

When example.com replies, the exit wraps the response in `RELAY_DATA` cells
and encrypts with hop 3's key. The middle adds hop 2's encryption. The guard
adds hop 1's encryption. The client peels all three layers and delivers the
plaintext to the browser.

No single relay sees both who you are and what you are accessing:
- The **guard** knows your IP but only sees encrypted data destined for the middle.
- The **middle** knows neither your IP nor the destination.
- The **exit** knows the destination but not your IP.

### Step 6: Congestion control

MOOR uses **Vegas** congestion control (Tor Proposal 324) with authenticated
SENDME digests (Prop 289) — each SENDME carries a 20-byte digest FIFO that
binds the ack to specific sent cells. Per-circuit `cwnd` starts at 124 cells,
queue delay drives slow-start / steady-state transitions, and per-stream
flow control (Prop 344) exposes `RELAY_XON` / `RELAY_XOFF` for independent
stream pausing.

### Step 7: Circuit rotation

After ~10 minutes MOOR stops assigning new streams to a circuit and builds
a fresh one. Old circuits tear down once existing streams finish. This bounds
the window during which traffic can be correlated.

## Cell format

Every cell on the wire is exactly **514 bytes** (plus 16-byte AEAD tag +
2-byte length prefix = 532 bytes encrypted). Fixed-size cells prevent
length-based traffic analysis.

```
Cell (514 bytes):
  +-------------------+-------------------------------------------+
  | circuit_id (4)    | command (1) | payload (509)               |
  +-------------------+-------------------------------------------+
  Header: 5 bytes                    Payload: 509 bytes

Relay payload (inside the 509-byte payload):
  +--------+------------+-----------+----------+--------+---------+
  | cmd(1) | recognized | stream_id | digest   | length | data    |
  |        | (2)        | (2)       | (4)      | (2)    | (498)   |
  +--------+------------+-----------+----------+--------+---------+
  Relay header: 11 bytes                         Data: up to 498 bytes
```

**Cell commands:**

| Command | ID | Description |
|---|---|---|
| PADDING | 0 | Padding cell (ignored by receiver) |
| CREATE | 1 | Classical CREATE (X25519 CKE) |
| CREATED | 2 | Classical CREATED |
| RELAY | 3 | Relay cell (carries data through circuit) |
| DESTROY | 4 | Tear down circuit |
| NETINFO | 5 | Peer info exchange |
| CREATE_PQ | 6 | PQ hybrid CREATE (X25519 + ML-KEM-768) |
| CREATED_PQ | 7 | PQ hybrid CREATED |
| KEM_CT | 8 | ML-KEM ciphertext fragment (PQ hybrid handshake) |
| RELAY_EARLY | 9 | Relay cell allowed to carry EXTEND (max 8 per circuit) |

**Digest verification.** Each relay cell carries a 4-byte truncated BLAKE2b
digest computed over a running hash of all cells on that circuit. The receiver
checks `BLAKE2b(running_state || payload_with_zeroed_digest)` against the
digest field. If the `recognized` field is zero and the digest matches, the
cell is for this hop; otherwise it is forwarded to the next hop.

## Consensus

Text-based format rebuilt hourly by directory authorities. Each DA signs with
both Ed25519 **and** ML-DSA-65 (post-quantum). Verification is sequential-AND.
Relays are sorted by identity key.

```
moor-consensus 1
valid-after 2026-04-20 12:00:00
fresh-until 2026-04-20 12:30:00
valid-until 2026-04-20 13:00:00
known-flags Authority BadExit Exit Fast Guard HSDir MiddleOnly Running Stable Valid
shared-rand-current-value <base64>
shared-rand-previous-value <base64>
n DROPOUT <b64(identity_pk)> 2026-04-20 12:00:00 86.54.28.132 9001 0
o <b64(onion_pk)>
a [2001:db8::1]:9001
k <b64(kem_pk)>
s Guard Running Stable Valid Fast
w Bandwidth=1000000 Measured=500000
g NL 1234
f <b64(family_id)>
p <b64(relay_signature)>
directory-footer
directory-signature <b64(da_identity_pk)> <b64(ed25519_sig)>
pq-directory-signature <b64(da_identity_pk)>
<b64(mldsa_pk)>
<b64(mldsa_sig)>
```

DA-to-DA communication uses encrypted channels: ephemeral Curve25519 DH +
HKDF, then AEAD-framed messages with length prefixes.

**Build-ID fleet gate.** Every descriptor carries a 16-byte git-hash build
ID. Directory authorities reject descriptors whose build_id differs from
theirs; mixed-commit fleets cannot form. Cryptographic changes ship with
a coordinated upgrade or not at all.

## Hidden services

Hidden services host a local TCP server reachable without revealing the
server's IP. Addresses are PQ-committed:

```
base32( Ed25519_pk(32) || BLAKE2b_16( ML-KEM_pk(1184) || Falcon_pk(897) ) ) + ".moor"
```

Both post-quantum public keys — the ML-KEM-768 encapsulation key and the
Falcon-512 signing key — are hashed into the onion address itself. Swapping
either key invalidates the address.

### Publishing (HS side)

1. Generate Ed25519 identity, Curve25519 onion, ML-KEM-768, and Falcon-512
   keypairs.
2. Derive a blinded keypair from the Ed25519 identity and the current time
   period (24-hour rotation).
3. Build 3-hop circuits to 6 introduction points using **vanguards**:
   layer-2 (4 relays, rotated every 24 h) and layer-3 (8 relays, rotated
   every ~1 h) to resist guard-discovery via time correlation.
4. Send `RELAY_ESTABLISH_INTRO` to each intro point.
5. Build an encrypted descriptor containing the intro-point list and onion key.
   Encrypt with a key derived from `identity_pk || time_period`. Sign **twice**
   — once with Ed25519 and once with Falcon-512. Verification is
   sequential-AND: both signatures must validate. The descriptor revision
   counter is floored to wall-clock time so a warm client rev-cache cannot
   wedge the service after a restart.
6. Publish the descriptor to the **DHT**: 3 replicas on the relays closest to
   `BLAKE2b(address_hash || epoch_nonce)` on the hash ring. The ring position
   rotates each epoch based on the consensus shared random value.

### Connecting (client side)

1. Compute the address hash from the `.moor` address and locate the 3
   responsible DHT relays.
2. Fetch the descriptor via **PIR**. MOOR supports two modes:
   - **2-server XOR-PIR**: the client sends a 256-bit bitmask query; the relay
     XOR-aggregates all matching entries.
   - **DPF-PIR**: Boyle-Gilboa-Ishai distributed-point-function pair queries
     to two replicas for stronger privacy on larger descriptor sets.
   Either way, the storing relay cannot learn which onion was requested.
3. Verify **both** signatures on the descriptor (Ed25519 and Falcon-512) and
   verify the BLAKE2b-16 commit in the `.moor` address matches
   `BLAKE2b_16(ML-KEM_pk || Falcon_pk)` from the descriptor body.
4. Decrypt the descriptor using the key derived from the `.moor` address.
5. Build a 3-hop circuit to a **rendezvous point** (any Running relay) and
   send `RELAY_ESTABLISH_RENDEZVOUS` with a 20-byte random cookie.
6. Build a circuit to one of the HS's intro points and send `RELAY_INTRODUCE1`.
   The INTRODUCE1 payload is **ML-KEM-768 sealed** to the service's KEM key:
   the client encapsulates a fresh shared secret under the HS's ML-KEM pk,
   derives an AEAD key from the KEM output + X25519 ECDH, and wraps the
   rendezvous cookie, RP address, and one-time handshake key inside
   ChaCha20-Poly1305. The wire layout is
   `kem_ct (1088) || aead_ct || aead_tag (16)`.
7. The intro point forwards `RELAY_INTRODUCE2` to the HS.
8. The HS decapsulates the KEM ciphertext with its ML-KEM secret, decrypts
   the AEAD, builds a circuit to the rendezvous point, and sends
   `RELAY_RENDEZVOUS1` with the cookie.
9. The rendezvous point matches cookies and splices the two circuits.
10. End-to-end encrypted data flows: client → 3 hops → RP → 3 hops → HS →
    localhost service.

Total path length: 6 hops (3 client-side + 3 HS-side) with the rendezvous
point in the middle.

## Cryptographic primitives

| Primitive | Algorithm | Source |
|---|---|---|
| Identity signing | Ed25519 | libsodium |
| PQ consensus signing | ML-DSA-65 (FIPS 204) | vendored PQClean |
| PQ HS descriptor signing | Falcon-512 (FN-DSA) | vendored PQClean |
| PQ HS INTRODUCE1 co-sig | Falcon-512 | vendored PQClean |
| Key exchange | X25519 | libsodium |
| PQ KEM | ML-KEM-768 (FIPS 203) | vendored PQClean |
| Link AEAD | XChaCha20-Poly1305 | libsodium |
| Circuit stream cipher | ChaCha20 | libsodium |
| Hash | BLAKE2b-256 | libsodium |
| KDF | HKDF-BLAKE2b | libsodium |
| PoW | Argon2id | libsodium |

## Key sizes

| Key | Bytes | Algorithm |
|---|---|---|
| Identity public key | 32 | Ed25519 |
| Identity secret key | 64 | Ed25519 |
| Onion public key | 32 | Curve25519 |
| ML-KEM public key | 1184 | ML-KEM-768 |
| ML-KEM secret key | 2400 | ML-KEM-768 |
| ML-KEM ciphertext | 1088 | ML-KEM-768 |
| ML-KEM shared secret | 32 | ML-KEM-768 |
| ML-DSA public key | 1952 | ML-DSA-65 |
| ML-DSA secret key | 4032 | ML-DSA-65 |
| ML-DSA signature | 3309 | ML-DSA-65 |
| Falcon public key | 897 | Falcon-512 |
| Falcon secret key | 1281 | Falcon-512 |
| Falcon signature | ~666 | Falcon-512 (variable) |
| Ed25519 signature | 64 | Ed25519 |
| Cell size (plaintext) | 514 | 5 header + 509 payload |
| Cell size (wire) | 532 | 2 length + 514 cell + 16 AEAD tag |

## Internal limits

| Limit | Value | Category |
|---|---|---|
| Max relays in consensus | 8192 | Internal |
| Max active circuits | 1024 | Internal |
| Max TCP connections | 1024 | Internal |
| Max streams per circuit | 64 | Internal |
| Max intro points per HS | 10 (default 6) | Internal |
| Max directory authorities | 9 | Internal |
| Circuit build timeout | 60 seconds | Timing |
| Link handshake timeout | 30 seconds | Timing |
| Consensus publish interval | 3600 seconds (1 hour) | Timing |
| Circuit rotation | 600 seconds (~10 min) | Timing |
| Guard rotation | 120 days | Timing |
| Vanguard L2 rotation | 24 hours | Timing |
| Vanguard L3 rotation | ~1 hour | Timing |
| HS time period (key blinding) | 24 hours | Timing |
| SENDME increment | 100 cells | Protocol |
| Circuit SENDME window | 1000 cells | Tunable |
| Stream SENDME window | 100 cells | Tunable |
| Initial congestion window | 124 cells | CC |
| Min congestion window | 100 cells | CC |
| Max congestion window | 2000 cells | CC |
| Max FDs (Linux/epoll) | 8192 | Internal |
| Max FDs (other) | 1024 | Internal |
| Network liveness timeout | 90 seconds | Timing |

## Traffic-analysis resistance

MOOR layers several defenses:

1. **Fixed-size cells** (514 bytes) — defeat length fingerprinting.
2. **Link-level PADDING cells** — fill inter-cell gaps.
3. **WTF-PAD machines** — Markov adaptive padding (web / stream / generic)
   with per-circuit randomized parameters.
4. **Constant-rate floor** — optional minimum cover rate.
5. **FRONT padding** — Rayleigh-sampled front padding over the first 5 s.
6. **Volume padding** — cells-per-circuit padded to the next power of two.
7. **EWMA scheduling** — per-circuit exponentially-weighted multiplexing
   prevents starvation under contention.
8. **Poisson mixing** — optional relay-side exponential-delay pool with
   cover cells.
9. **Conflux** (Prop 329) — up to 4 circuit legs bonded per set with Feistel
   PRP sequence encoding and reorder buffer. SKIPS RTT-adaptive scheduling
   picks the lowest-latency leg at each send.
10. **Pluggable transports** — six cover-traffic transports hide the fact
    that MOOR is in use at all (see below).
11. **Scanner honeypot** — non-bridge relays intercept ORPort probes matching
    well-known DPI fingerprints (HTTP, SSH, SCADA) and return rotating fake
    industrial-control banners, poisoning scanning datasets. Gated on
    `!g_is_bridge` so legitimate cover-traffic prefixes pass through bridge
    ORPorts untouched.

## Pluggable transports

| Transport | Technique | Looks like on the wire |
|-----------|-----------|------------------------|
| **ShitStorm** | Chrome 146 JA4 + Elligator2 + ECH GREASE + HTTP/2 | Chrome browsing a CDN |
| **Nether** | Minecraft 1.21.4 handshake + login + plugin channels | Minecraft gameplay |
| **Mirage** | TLS 1.3 with real X25519 DH + configurable SNI | HTTPS to any domain |
| **Shade** | Elligator2 key obfuscation + IAT modes | Random bytes |
| **Scramble** | ASCII HTTP/1.1 GET prefix + ChaCha20 stream | HTTP traffic |
| **Speakeasy** | SSH-2.0 banner + KEX + encrypted channel framing | SSH session |

Select one per bridge with `--bridge-transport`.

## Bridge support

- **Bridge relays** run with `--is-bridge`, are not published in the public
  consensus, and skip the scanner honeypot so transport cover prefixes pass
  through.
- **Bridge authority** tracks bridge descriptors and forwards to BridgeDB.
- **BridgeDB** is an HTTP endpoint that deterministically assigns bridges
  per client IP (keyed BLAKE2b hash).
- **Clients** set `UseBridges 1` and one or more `Bridge` lines naming a
  transport + address + fingerprint.

## OnionBalance

OnionBalance mode (`--mode ob`) aggregates intro points from multiple HS
backend instances under a single `.moor` address, giving a hidden service
load distribution and redundancy.

## Control port

MOOR implements a Tor-compatible control protocol:
- `AUTHENTICATE` (cookie or password)
- `GETINFO` (version, traffic/read, traffic/written, circuit-status,
  stream-status, stats)
- `SETEVENTS` (CIRC, STREAM, BW)
- `SIGNAL NEWNYM` (clear circuit cache) and `SIGNAL SHUTDOWN`
- Async events: `650 CIRC`, `650 STREAM`, `650 BW`

## Sandboxing and memory hygiene

- **seccomp-bpf** syscall allow-list, `no_new_privs`, per-mode `rlimit`s.
- **mlockall(MCL_CURRENT)** pins currently-mapped pages so secret key
  material does not leak to swap. `MCL_FUTURE` is deliberately not set —
  it interacts badly with pthread stack allocation under typical
  `RLIMIT_MEMLOCK` limits.
- `sodium_memzero` on every derived-key buffer after use.
- Identity and onion private keys are generated with `arc4random`/libsodium
  RNG, never touched except by the signing / DH path.
