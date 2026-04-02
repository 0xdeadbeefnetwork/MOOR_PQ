# MOOR

Post-quantum anonymous overlay network. Version 0.8.0.

## What is this?

MOOR is an onion router. Your traffic is encrypted in three layers and routed through three relays. Each relay peels one layer, learns only the next hop, and forwards. No single relay knows both who you are and what you're accessing.

Every key exchange — link, circuit, hidden service — uses hybrid post-quantum cryptography: X25519 + Kyber768. Traffic recorded today cannot be decrypted by a quantum computer tomorrow.

~40,000 lines of C. Three dependencies (libsodium, zlib, pthreads). No OpenSSL.

### What each relay sees

```
You  --->  Guard  --->  Middle  --->  Exit  --->  Destination
           sees:        sees:         sees:
           your IP      nothing       destination
           NOT where    useful.       NOT your IP.
           you're       just passes   makes the
           going.       encrypted     connection
                        data along.   on your behalf.
```

## Pluggable transports

MOOR includes four pluggable transports for censorship circumvention, plus one in design:

### ShitStorm (recommended)

The most advanced transport. Combines every evasion technique into a single layer:

- **Chrome 130 JA4 fingerprint** — ClientHello matches real Chrome with ECH GREASE, 15 cipher suites, Fisher-Yates shuffled extensions
- **Elligator2 key material** — x25519 key_share bytes are indistinguishable from random (no curve point structure)
- **Double AEAD encryption** — Outer ChaCha20-Poly1305 (TLS records) + inner ChaCha20-Poly1305 (length-obfuscated payloads)
- **HTTP/2 framing** — Post-handshake data wrapped in h2 connection preface + SETTINGS + DATA frames
- **Fake session resumption** — PSK binder + 2 NewSessionTicket messages (no "always full handshake" fingerprint)
- **Dynamic SNI discovery** — GeoIP + CDN seed resolution, ISP PTR filtering, per-country CDN intelligence
- **Key rotation** — All keys ratcheted every 65,536 records via BLAKE2b
- **Replay cache** — 4,096 entries with BLAKE2b hash-based slot placement, 600s TTL
- **Cert chain realism** — Fake encrypted handshake records sized 3,500-5,500 bytes (matches Let's Encrypt RSA chains)

A DPI box sees Chrome 130 doing TLS 1.3 to a CDN. Blocking it means blocking Chrome.

```
./moor --UseBridges 1 --Bridge "shitstorm 1.2.3.4:9001 <fingerprint>"
```

### Scramble

Entropy evasion. ASCII HTTP prefix followed by ChaCha20-encrypted payload. Defeats entropy-based filters (GFW's fully-encrypted-traffic detector).

### Shade

Statistical evasion. Elligator2 constant-time key generation with IAT obfuscation modes. Defeats statistical classifiers on key exchange bytes.

### Mirage

Protocol evasion. Full TLS 1.3 record framing with real x25519 key_share, configurable SNI, session_id HMAC for probe resistance.

### WebWTF (in design)

UDP-based transport mimicking a WebRTC video call. STUN + DTLS + SRTP with Opus/VP8 payload types. MOOR cells hidden inside media packets. Blocking it means blocking Zoom, Meet, and Discord. See [docs/webwtf-design.md](docs/webwtf-design.md).

## Cryptography

| Layer | Algorithm | What it protects |
|-------|-----------|-----------------|
| Link handshake | Noise_IK + Kyber768 | Connection to first relay |
| Circuit key exchange | X25519 + Kyber768 hybrid CKE | Each hop of the 3-hop path |
| HS end-to-end | X25519 + Kyber768 (post-handshake KEM) | Client to hidden service |
| Onion encryption | ChaCha20 (PQ hybrid derived keys) | Data through the circuit |
| Consensus signatures | Ed25519 + ML-DSA-65 (Dilithium3) | Relay directory integrity |
| Identity keys | Ed25519 | Relay and service identity |
| KEM | ML-KEM-768 (Kyber768) | Post-quantum key encapsulation (NIST Level 3) |
| PQ signatures | ML-DSA-65 (Dilithium3) | Post-quantum signature verification |
| Exit DNS | DNSCrypt v2 (X25519 + XSalsa20-Poly1305) | Encrypted DNS at exit relay |

Every layer uses hybrid PQ crypto. An attacker must break both X25519 and Kyber768 to decrypt anything.

## Traffic analysis resistance

- **Fixed-size cells** — 514 bytes. A 10-byte message and a 498-byte page look identical.
- **WTF-PAD adaptive padding** — Randomized per-circuit padding machines (web, stream, generic presets).
- **Poisson relay mixing** — Configurable random delay per relay before forwarding.
- **Conflux multi-path** — Split traffic across multiple circuit paths simultaneously.
- **Constant-rate padding** — Cover traffic when idle.

## Hidden services

Host a `.moor` service reachable only through the network:

```
./moor --mode hs --hs-dir ./hs_keys --hs-port 8080 -v
```

- 6-hop tunnel (3 client + 3 service) with PQ hybrid end-to-end encryption
- DPF-PIR for anonymous descriptor lookups (neither storage relay learns which service you requested)
- Vanguard relays protect against guard discovery
- Proof-of-work prevents introduction flooding
- OnionBalance for load balancing across backends

## Network infrastructure

- **Multi-DA consensus voting** — Multiple directory authorities with Ed25519 + ML-DSA-65 dual signatures
- **Bridge relays** — Unlisted relays for censorship circumvention, excluded from public consensus
- **GeoIP path diversity** — No two relays in a circuit share the same country or AS
- **Bandwidth-weighted relay selection** — Tor-aligned flag assignment (Guard, Fast, Stable, Exit)
- **Argon2id PoW** — Memory-hard proof-of-work prevents Sybil attacks
- **Connection reaper** — Aggressive TCP keepalive + idle connection cleanup for long-running stability
- **seccomp sandbox** — PR_SET_NO_NEW_PRIVS, rlimits, dumpable=0

## Quick start

### Client (browse anonymously)

```bash
sudo apt install build-essential libsodium-dev zlib1g-dev
make
./moor
# SOCKS5 proxy on 127.0.0.1:9050
curl -x socks5h://127.0.0.1:9050 http://example.com
```

### Client through a bridge (censorship circumvention)

```bash
./moor --UseBridges 1 --Bridge "shitstorm 1.2.3.4:9001 <fingerprint>" -v
```

### Relay

```bash
curl -sL https://raw.githubusercontent.com/0xdeadbeefnetwork/MOOR_PQ/main/setup.sh | sudo bash
```

Or manually:

```bash
./moor --mode relay --advertise 1.2.3.4 --nickname MYRELAY -v
./moor --mode relay --exit --advertise 1.2.3.4 --nickname MYEXIT -v
```

### Bridge relay

```bash
./moor --mode relay --is-bridge --bridge-transport shitstorm --advertise 1.2.3.4 --nickname MYBRIDGE -v
```

Bridge line printed on startup. Give it to users who need censorship circumvention.

## Current network

| Node | Role | Location |
|------|------|----------|
| DA1 | Directory Authority | US |
| DA2 | Directory Authority | US |
| TURBINE | Guard relay | US |
| DROPOUT | Guard relay | NL |
| VALIDATOR | Exit relay | NL |
| PIBRIDGE | ShitStorm bridge | US (residential) |

## Key persistence

Node keys are stored in `--data-dir <path>/keys/`. Back up this directory to preserve identity across restarts, upgrades, and server migrations. Keys are tied to nothing but the files — not the IP, hostname, or hardware.

## Source

https://github.com/0xdeadbeefnetwork/MOOR_PQ

~40,000 lines of C across 43 source files. ~3,600 lines of vendored NIST PQ reference implementations (Kyber768, Dilithium3).

## License

See LICENSE file.
