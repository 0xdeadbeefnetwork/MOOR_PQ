# Architecture

## Overview

MOOR is a single C binary that operates in one of seven modes: **client**, **relay**, **directory authority (DA)**, **hidden service (HS)**, **OnionBalance (OB)**, **BridgeDB**, or **bridge authority**. All modes share the same crypto, cell, connection, and event loop infrastructure. The binary is portable across Linux (with epoll) and Windows (with select/WSAPoll).

Version: 0.7.0

## Source layout

```
src/
  main.c              Entry point, CLI/config parsing, mode dispatch, event loop setup
  log.c               Leveled logging (DEBUG/INFO/WARN/ERROR/FATAL) with timestamps
  crypto.c            Ed25519 sign/verify, X25519 DH, ChaCha20-Poly1305 AEAD, BLAKE2b
                      hash, HKDF, key exchange, key blinding, Ed-to-Curve conversion
  kem.c               Kyber768 (ML-KEM-768) KEM wrapper: keygen, encapsulate, decapsulate
  sig.c               ML-DSA-65 (Dilithium3) wrapper: keygen, sign, verify
  cell.c              Fixed 514-byte cell pack/unpack, relay payload pack/unpack,
                      CREATE/CREATED/DESTROY builders, rolling BLAKE2b digest
  connection.c        TCP listener, connection pool (1024 slots), hash table (2048 Fibonacci),
                      Noise_IK link handshake + Kyber768 hybrid, AEAD cell send/recv,
                      transport-aware I/O, dual-stack IPv4/IPv6
  circuit.c           Circuit pool (1024 slots), hash table (4096 Fibonacci),
                      CREATE/EXTEND (CKE: X25519 DH), CREATE_PQ/EXTEND_PQ (+ Kyber768 KEM),
                      path selection (bandwidth-weighted, GeoIP-diverse, guard pinning),
                      vanguards (L2/L3), congestion control (Vegas/Prop 324), CBT,
                      path bias detection, OOM killer, async builder thread
  relay.c             Relay cell processing, CREATE/EXTEND handlers, exit connections,
                      exit policy enforcement, SSRF protection (private addr rejection),
                      async EXTEND (worker thread), relay registration, DNS cache integration
  node.c              Descriptor create/serialize/sign, consensus parse/serialize,
                      microdescriptor support, relay selection helpers
  directory.c         DA consensus building, vote exchange, encrypted DA-to-DA channel
                      (ephemeral DH + AEAD), relay registration, Ed25519 + ML-DSA-65
                      dual signing, GeoIP flag assignment
  socks5.c            SOCKS5 proxy server, stream management, circuit isolation
                      (per-domain), prebuilt circuit pool (8 slots) + background builder
                      thread, HS .moor address detection, conflux integration
  hidden_service.c    HS keygen (Ed25519 + Curve25519), key blinding (time-period rotation),
                      intro point establishment (with vanguards), descriptor encryption
                      (AEAD with derived key), rendezvous protocol, .moor addresses
                      (base32(identity_pk) + ".moor")
  dht.c               Distributed hash table for HS descriptors: ring position computation
                      (BLAKE2b), XOR distance, responsible relay selection, PIR fetch
                      (bitmask query + XOR-aggregated response), 3 replicas per epoch
  config.c            Config file parser (Tor-compatible syntax: "Key Value"), exit policy
                      parser, external IP auto-detection (connected UDP getsockname trick)
  event.c             Event loop: epoll on Linux, select on Windows, with timer support
  transport.c         Pluggable transport registry (max 4 transports)
  transport_scramble.c Scramble: randomized obfuscation, DH + HMAC handshake, ChaCha20
                      framed transport with random padding and header encryption
  transport_shade.c   Shade: Elligator2-inspired key obfuscation, mark/MAC handshake,
                      ChaCha20-Poly1305 AEAD framing, IAT modes (none/delay/fragment)
  transport_mirage.c  Mirage: TLS 1.3 camouflage, fake ClientHello/ServerHello with real
                      x25519 DH, variable-length TLS Application Data records
  geoip.c             Tor-compatible GeoIP database parser (IPv4/IPv6), country code +
                      AS number lookup via binary search
  fragment.c          Cell fragmentation for oversized payloads (KEM data): fragment ID,
                      sequence numbers, reassembly state machine
  pow.c               Argon2id proof-of-work for relay admission DoS protection,
                      nonce replay cache (4096 slots), configurable difficulty + memory
  padding_adv.c       Three-layer padding: constant-rate (50ms), adaptive burst cover,
                      jitter delay
  wfpad.c             WTF-PAD adaptive padding: Markov chain state machines (web/stream/
                      generic), per-circuit randomized parameters, constant-rate base
                      layer, FRONT randomized front padding, volume padding (power-of-2)
  mix.c               Poisson mixing: exponential-delay pool for relayed cells, cover
                      cell injection, per-circuit ordering preservation
  conflux.c           Multi-path circuit bonding (up to 4 legs), Feistel PRP for sequence
                      number encryption, reorder buffer (32 slots)
  bw_auth.c           Bandwidth authority: relay measurement, effective bandwidth
                      calculation (self-reported capped at 1.2x measured)
  ratelimit.c         Per-IP token bucket rate limiting: connection, circuit, intro,
                      establish, rendezvous (LRU eviction when table full)
  scheduler.c         Cell output queue (ring buffer), round-robin scheduling across
                      circuits
  monitor.c           Runtime stats (connections, circuits, bytes), Tor-compatible control
                      port (AUTHENTICATE, GETINFO, SETEVENTS, SIGNAL NEWNYM/SHUTDOWN)
  dns_cache.c         Exit-side DNS cache with TTL expiry
  bootstrap.c         Bootstrap progress reporting ("Bootstrapped N%: phase"), network
                      liveness detection (90s timeout)
  transparent.c       TransPort (iptables REDIRECT + SO_ORIGINAL_DST) + DNSPort (UDP DNS
                      resolution through exit relay) for transparent proxying
  addressmap.c        Virtual address mapping: .moor hostnames to 127.192.0.0/10 IPs
                      for TransPort integration
  onionbalance.c      OnionBalance: aggregate intro points from multiple HS backends
                      under a single .moor address
  bridgedb.c          Bridge distribution service: deterministic bridge assignment per
                      client IP (keyed BLAKE2b hash), minimal HTTP endpoint
  bridge_auth.c       Bridge authority: bridge registration, descriptor storage
  exit_sla.c          Exit relay SLA monitoring: per-relay success rate, latency tracking,
                      scoring (0-100)
  crypto_worker.c     Threaded crypto offload: CKE DH computation in worker pool,
                      results via pipe (Unix) or loopback socket pair (Windows)

  kyber/              Vendored Kyber768 (ML-KEM-768) reference implementation
  dilithium/          Vendored Dilithium3 (ML-DSA-65) reference implementation

include/moor/
  moor.h              Master header: version, identity/key length constants, node flags,
                      mode enum, padding/BW/conflux/vanguard constants
  limits.h            All capacity/timing/protocol limits in one file (protocol-fixed,
                      tunable, internal)
  cell.h              Cell commands, relay commands, destroy/end reason codes, cell/relay
                      payload structs
  [module].h          Per-module public API and struct definitions
```

## How browsing through MOOR works (step by step)

This section walks through what happens when you open a web browser, point it at MOOR's SOCKS5 port, and visit a website. Every step is explained so someone new to onion routing can follow along.

### Step 0: Starting up

When you launch `moor` with no arguments, it starts in client mode and listens for SOCKS5 connections on port 9050 (same as Tor). It also spawns a background builder thread that pre-builds circuits so they are ready when you need them.

During startup, the client:

1. Initializes libsodium (the crypto library).
2. Generates or loads an Ed25519 identity keypair.
3. Connects to a directory authority (DA) and downloads the **consensus** -- a signed list of all relays in the network, including their addresses, public keys, bandwidth, flags, and country codes.
4. Verifies the consensus carries valid Ed25519 + ML-DSA-65 dual signatures from the DAs.
5. Begins pre-building 3-hop circuits in the background so they are ready when you browse.

The client prints Tor-style progress:
```
Bootstrapped 10%: Connecting to a relay
Bootstrapped 25%: Performing link handshake
Bootstrapped 40%: Requesting network consensus
Bootstrapped 70%: Establishing a circuit
Bootstrapped 100%: Done
```

### Step 1: Your browser connects to MOOR

Your browser is configured to use `127.0.0.1:9050` as a SOCKS5 proxy. When you visit `https://example.com`, the browser opens a TCP connection to MOOR and sends a SOCKS5 CONNECT request saying "please connect me to example.com:443".

MOOR's SOCKS5 server (`socks5.c`) accepts this request. It checks its circuit cache for a circuit already assigned to `example.com` (circuit isolation -- different websites use different circuits so the exit relay cannot correlate your visits). If none exists, it grabs a pre-built circuit from the pool.

### Step 2: Establishing a link to the guard relay

Before any circuit can be built, the client needs an encrypted TCP connection to the first relay (the **guard**). This uses the **Noise_IK** handshake, a well-studied authenticated key exchange:

```
Client already knows guard's Ed25519 public key (from the consensus).

  Client -> Guard:  ephemeral_pk(32) + encrypted(client_static_pk)(48)    [80 bytes]
  Guard  -> Client: ephemeral_pk(32) + encrypted(empty+MAC)(16)           [48 bytes]
```

After Noise_IK, both sides have symmetric send/recv keys derived from three DH operations. But these keys are only secure against classical computers.

To defend against quantum computers, MOOR immediately performs a **Kyber768 KEM exchange** over the now-encrypted link:

```
  Client -> Guard:  kyber_pk (1184 bytes, encrypted)
  Guard  -> Client: kyber_ct (1088 bytes, encrypted)
```

Both sides decapsulate and mix the KEM shared secret into the existing link keys via HKDF. The link is now resistant to both classical and quantum adversaries.

Every cell sent over this link is encrypted with **ChaCha20-Poly1305 AEAD** (16-byte authentication tag). On the wire, each cell is 532 bytes: a 2-byte length prefix + 514 bytes of cell plaintext + 16 bytes of AEAD tag.

### Step 3: Building a 3-hop circuit

With the encrypted link to the guard established, the client builds a circuit through three relays: **guard**, **middle**, and **exit**. These three relays are chosen carefully:

- **Guard**: Selected from relays with the Guard flag, bandwidth-weighted (faster relays are more likely to be picked). The client pins its guard for 120 days to limit exposure. If GeoIP data is loaded, the guard is chosen from a different country/AS than the other hops.
- **Middle**: Any relay with the Running flag, excluding the guard and same-family relays. Different country/AS from guard and exit.
- **Exit**: A relay with the Exit flag whose exit policy allows the destination port.

**Hop 1 (to guard):** The client sends a `CREATE_PQ` cell containing its X25519 ephemeral public key and the relay's identity key. The guard performs an X25519 DH, derives circuit keys via HKDF, and replies with `CREATED_PQ`. Then a Kyber768 KEM exchange follows (RELAY_KEM_OFFER + RELAY_KEM_ACCEPT), and the KEM shared secret is mixed into the circuit keys. The client now has forward/backward ChaCha20 stream cipher keys for hop 1.

**Hop 2 (to middle):** The client wraps an `EXTEND` command in a relay cell, encrypts it with hop 1's key, and sends it. The guard decrypts one layer, sees the EXTEND, and opens a new TCP connection to the middle relay (with its own Noise_IK + Kyber768 link handshake). The guard forwards the CREATE to the middle, receives CREATED, and sends RELAY_EXTENDED back to the client. The client now has circuit keys for hop 2. The guard cannot read hop 2's encrypted content.

**Hop 3 (to exit):** Same as hop 2, but the EXTEND goes through both the guard and middle to reach the exit relay. The client now holds three sets of symmetric keys, one per hop.

```
Client --- [hop 1 keys] --- Guard --- [hop 2 keys] --- Middle --- [hop 3 keys] --- Exit
```

### Step 4: Sending your web request

The client sends a `RELAY_BEGIN` cell to tell the exit relay to connect to `example.com:443`. The cell payload travels through three layers of encryption:

```
Plaintext: RELAY_BEGIN "example.com:443"
  -> encrypt with hop 3 key (exit)
  -> encrypt with hop 2 key (middle)
  -> encrypt with hop 1 key (guard)
  = fully encrypted cell on the wire
```

The guard decrypts one layer and forwards to the middle. The middle decrypts one layer and forwards to the exit. The exit decrypts the final layer, sees the RELAY_BEGIN, and opens a TCP connection to example.com:443. It sends back `RELAY_CONNECTED`.

Your browser's TLS handshake with example.com then flows as `RELAY_DATA` cells through the circuit. Each cell carries up to 498 bytes of user data (509 bytes payload minus 11 bytes relay header).

### Step 5: Data flows back

When example.com sends data back, the exit relay wraps it in `RELAY_DATA` cells and encrypts with hop 3's key. The middle adds hop 2's encryption. The guard adds hop 1's encryption. The client peels all three layers and delivers the plaintext to the browser.

No single relay sees both who you are and what you are accessing:
- The **guard** knows your IP but only sees encrypted data destined for the middle.
- The **middle** knows neither your IP nor the destination -- it just forwards encrypted cells.
- The **exit** knows the destination but not your IP.

### Step 6: Congestion control

MOOR uses **Vegas congestion control** (Tor Proposal 324) to manage flow. Each circuit maintains a congestion window (`cwnd`, starting at 124 cells), tracks RTT, and adjusts the window based on queuing delay:

- **Slow start**: Increase cwnd until queue delay exceeds the gamma threshold.
- **Steady state**: If queue delay < alpha, increase; if > beta, decrease; otherwise hold.
- **SENDME cells**: Every 100 cells, the receiver sends a SENDME acknowledgment. The sender cannot send beyond the circuit window (default 1000 cells) without receiving SENDMEs.
- **XON/XOFF**: Per-stream flow control (Prop 344). A stream can be paused (XOFF) or resumed (XON) independently.

### Step 7: Circuit rotation

After 10 minutes, MOOR stops assigning new streams to the circuit and builds a fresh one. Old circuits are torn down after existing streams finish. This limits the window during which traffic can be correlated.

## Cell format

Every cell on the wire is exactly **514 bytes** (plus 16-byte AEAD tag + 2-byte length prefix = 532 bytes encrypted). Fixed-size cells prevent length-based traffic analysis.

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
| CREATE | 1 | Create circuit hop (X25519 CKE) |
| CREATED | 2 | Circuit hop created |
| RELAY | 3 | Relay cell (carries data through circuit) |
| DESTROY | 4 | Tear down circuit |
| NETINFO | 5 | Network information exchange |
| CREATE_PQ | 6 | Create circuit hop (X25519 + Kyber768 hybrid) |
| CREATED_PQ | 7 | PQ circuit hop created |
| RELAY_EARLY | 9 | Relay cell allowed to carry EXTEND (max 8 per circuit) |

**Digest verification:** Each relay cell carries a 4-byte truncated BLAKE2b digest computed over a running hash of all cells on that circuit. The receiver checks `BLAKE2b(running_state || payload_with_zeroed_digest)` against the digest field. If the `recognized` field is zero and the digest matches, the cell is for this hop. Otherwise it is forwarded to the next hop.

## Consensus

Text-based format, rebuilt hourly by directory authorities. Each DA signs with both Ed25519 and ML-DSA-65 (post-quantum). Relays are sorted by identity key.

```
moor-consensus 1
valid-after 2026-03-28 12:00:00
fresh-until 2026-03-28 12:30:00
valid-until 2026-03-28 13:00:00
known-flags Authority BadExit Exit Fast Guard MiddleOnly Running Stable Valid
shared-rand-current-value <base64>
shared-rand-previous-value <base64>
n DROPOUT <b64(identity_pk)> 2026-03-28 12:00:00 86.54.28.132 9001 0
o <b64(onion_pk)>
a [2001:db8::1]:9001
k <b64(kem_pk)>
s Guard Running Stable Valid Fast
w Bandwidth=1000000 Measured=500000
g NL 1234
f <b64(family_id)>
p <b64(relay_signature)>
directory-footer
directory-signature <b64(da_pk)> <b64(ed25519_sig)>
pq-directory-signature <b64(da_pk)>
<b64(mldsa_pk)>
<b64(mldsa_sig)>
```

DA-to-DA communication uses encrypted channels: ephemeral Curve25519 DH + HKDF, then AEAD-framed messages with length prefixes.

## Hidden services

Hidden services let you host a server that is reachable without revealing its IP address. The server's address is `base32(identity_pk).moor`.

### Publishing (HS side)

1. Generate an Ed25519 identity keypair and a Curve25519 onion keypair.
2. Derive a blinded keypair from the identity key and the current time period (24-hour rotation).
3. Build 3-hop circuits to 6 introduction points using **vanguards**: layer-2 (4 relays, rotated every 24h) and layer-3 (8 relays, rotated every 1h) to protect against guard discovery attacks.
4. Send `ESTABLISH_INTRO` to each intro point.
5. Build an encrypted descriptor containing the intro point addresses and onion key, encrypted with a key derived from `identity_pk + time_period`. Only someone who knows the .moor address can derive this key.
6. Publish the descriptor to the **DHT**: 3 replicas on the relays closest to `BLAKE2b(address_hash || epoch_nonce)` on the hash ring. The ring position rotates each epoch based on the shared random value from the consensus.

### Connecting (client side)

1. Compute the address hash from the .moor address and find the 3 responsible DHT relays.
2. Fetch the descriptor via **PIR** (Private Information Retrieval): the client sends a 256-bit bitmask query so the DHT relay cannot tell which descriptor was requested. The relay XOR-aggregates all matching entries and returns the result.
3. Decrypt the descriptor using the key derived from the .moor address.
4. Build a 3-hop circuit to a **rendezvous point** (any relay) and send `ESTABLISH_RENDEZVOUS` with a 20-byte random cookie.
5. Build a circuit to one of the HS's introduction points and send `INTRODUCE1` containing the rendezvous point address, cookie, and a one-time key for the end-to-end handshake.
6. The intro point forwards `INTRODUCE2` to the HS.
7. The HS builds a circuit to the rendezvous point and sends `RENDEZVOUS1` with the cookie.
8. The rendezvous point matches cookies and connects the two circuits.
9. End-to-end encrypted data flows: client -> 3 hops -> RP -> 3 hops -> HS -> localhost service.

Total path length: 6 hops (3 client-side + 3 HS-side), with the rendezvous point in the middle.

## Cryptographic primitives

| Primitive | Algorithm | Library |
|---|---|---|
| Identity signing | Ed25519 | libsodium |
| PQ signing | ML-DSA-65 (Dilithium3) | vendored dilithium/ |
| Key exchange | X25519 (Curve25519 DH) | libsodium |
| PQ KEM | Kyber768 (ML-KEM-768) | vendored kyber/ |
| Link AEAD | ChaCha20-Poly1305 | libsodium |
| Circuit stream cipher | ChaCha20 | libsodium |
| Hash | BLAKE2b-256 | libsodium |
| KDF | HKDF (BLAKE2b-based) | libsodium |
| PoW | Argon2id (256 KB memory) | libsodium |

## Key sizes

| Key | Bytes | Algorithm |
|---|---|---|
| Identity public key | 32 | Ed25519 |
| Identity secret key | 64 | Ed25519 |
| Onion public key | 32 | Curve25519 |
| KEM public key | 1184 | Kyber768 |
| KEM secret key | 2400 | Kyber768 |
| KEM ciphertext | 1088 | Kyber768 |
| KEM shared secret | 32 | Kyber768 |
| ML-DSA public key | 1952 | Dilithium3 |
| ML-DSA secret key | 4032 | Dilithium3 |
| ML-DSA signature | 3309 | Dilithium3 |
| Ed25519 signature | 64 | Ed25519 |
| Cell size (plaintext) | 514 | Fixed (5 header + 509 payload) |
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
| Circuit rotation | 600 seconds (10 min) | Timing |
| Guard rotation | 120 days | Timing |
| Vanguard L2 rotation | 24 hours | Timing |
| Vanguard L3 rotation | 1 hour | Timing |
| HS time period (key blinding) | 24 hours | Timing |
| SENDME increment | 100 cells | Protocol |
| Circuit SENDME window | 1000 cells | Tunable |
| Stream SENDME window | 100 cells | Tunable |
| Initial congestion window | 124 cells | CC |
| Min congestion window | 31 cells | CC |
| Max congestion window | 2000 cells | CC |
| Max FDs (Linux/epoll) | 8192 | Internal |
| Max FDs (other) | 1024 | Internal |
| Network liveness timeout | 90 seconds | Timing |

## Traffic analysis resistance

MOOR implements multiple layers of defense against traffic analysis:

1. **Fixed-size cells** (514 bytes) -- prevent length fingerprinting.
2. **Link-level padding** -- PADDING cells fill gaps in communication.
3. **WTF-PAD machines** -- adaptive padding state machines (web/stream/generic) with per-circuit randomized parameters to defeat machine learning classifiers.
4. **Constant-rate padding** -- optional 50ms floor to mask burst patterns.
5. **FRONT padding** -- Rayleigh-distributed front padding cells at circuit start.
6. **Poisson mixing** -- optional relay-side exponential delay pool with cover cells.
7. **Pluggable transports** -- Scramble (random bytes), Shade (Elligator2 obfuscation), Mirage (TLS 1.3 camouflage) hide the fact that MOOR is being used at all.

## Bridge support

Bridges are unlisted relays used to circumvent IP-based blocking of the MOOR network:

- **Bridge relays**: Run with `--is-bridge`, not listed in the public consensus.
- **Bridge authority**: Tracks bridge descriptors and distributes to BridgeDB.
- **BridgeDB**: HTTP endpoint that deterministically assigns bridges to clients based on their IP (keyed BLAKE2b hash), so the same client always gets the same bridges.
- **Clients**: Configure `UseBridges 1` and `Bridge "transport addr:port fingerprint"` to connect via bridges using pluggable transports.

## OnionBalance

OnionBalance mode (`--mode ob`) aggregates introduction points from multiple HS backend instances under a single .moor address, providing load distribution and redundancy for hidden services.

## Control port

MOOR implements a Tor-compatible control port protocol supporting:
- `AUTHENTICATE` (cookie or password)
- `GETINFO` (version, traffic/read, traffic/written, circuit-status, stream-status, stats)
- `SETEVENTS` (CIRC, STREAM, BW)
- `SIGNAL NEWNYM` (clear circuit cache) and `SIGNAL SHUTDOWN` (graceful shutdown)
- Async events: `650 CIRC`, `650 STREAM`, `650 BW`
