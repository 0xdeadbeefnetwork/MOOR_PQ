# MOOR

Post-quantum anonymous overlay network. Three-hop onion routing with hybrid classical + post-quantum cryptography on every data path.

## What it does

MOOR routes your traffic through three encrypted relays so no single point can see both who you are and what you're accessing.

```
You  --->  Guard  --->  Middle  --->  Exit  --->  Internet
           sees         sees          sees
           your IP      nothing       destination
```

- **Guard** — entry relay. Knows your IP, not your destination.
- **Middle** — forwards encrypted cells. Sees nothing useful.
- **Exit** — connects to the destination. Does not know your IP.

## Modes

MOOR is a single binary that runs as:

- **Client** — SOCKS5 proxy on localhost, builds circuits, fetches HS descriptors
- **Relay** — forwards encrypted cells (guard, middle, or exit)
- **Directory Authority (DA)** — publishes signed consensus with Ed25519 + ML-DSA-65 dual signatures
- **Hidden Service** — hosts a `.moor` service reachable only through the network (any TCP)
- **OnionBalance** — load-balances a hidden service across multiple backends
- **Bridge** — transport-wrapped entry point for censored networks

## Quick start

**Dependencies:** `build-essential libsodium-dev zlib1g-dev libevent-dev`

```bash
make
./moor                              # client: SOCKS5 on port 9050
```

Deploy a relay (one command):
```bash
curl -sL https://raw.githubusercontent.com/0xdeadbeefnetwork/MOOR_PQ/main/setup.sh | sudo bash
```

Deploy a relay (manual):
```bash
./moor --mode relay --advertise YOUR_IP --nickname MYRELAY -v
./moor --mode relay --advertise YOUR_IP --nickname MYRELAY --exit -v
./moor --mode relay --advertise YOUR_IP --nickname MYRELAY --guard -v
```

Hidden service:
```bash
./moor --mode hs --hs-port 8080 -v
```

Hidden service with port mapping:
```
# /etc/moor/moorrc
HiddenServiceDir   /var/lib/moor/hidden_service
HiddenServicePort  80 8080
HiddenServicePort  22
```

Browse through MOOR:
```bash
curl -x socks5h://127.0.0.1:9050 http://example.com
```

SSH to a hidden service:
```bash
proxychains ssh user@<onion>.moor
```

Connect through a bridge:
```bash
./moor --UseBridges 1 --Bridge "shitstorm 1.2.3.4:9001 <fingerprint>" -v
```

## Relay types

| Type | Flag | What it does | What it sees | Risk |
|------|------|-------------|-------------|------|
| Relay | (none) | General purpose, DA assigns role by performance | Depends | Low |
| Middle | `--middle-only` | Only middle hop, never guard or exit | Nothing useful | Lowest |
| Guard | `--guard` | Entry point for client circuits | Client IPs, not destinations | Low |
| Exit | `--exit` | Forwards traffic to the internet | Destinations, not client IPs | Gets abuse complaints |

Under 20 relays: self-declared flags are trusted immediately. At 20+ relays: Prop 271 guard pinning activates and guards must earn the flag (Fast + Stable + bandwidth + 8-day uptime requirement).

## Crypto

| Layer | Classical | Post-Quantum |
|-------|-----------|--------------|
| Link handshake | Noise_IK (X25519 + XChaCha20-Poly1305 + BLAKE2b) | ML-KEM-768 post-handshake KEM |
| Circuit key exchange | X25519 ECDH | ML-KEM-768 (CELL_KEM_CT fragmented) |
| Cell encryption | ChaCha20 stream | — (keys PQ-derived) |
| HS end-to-end | X25519 + ChaCha20-Poly1305 AEAD | ML-KEM-768 sealing on INTRODUCE1 |
| HS identity | Ed25519 descriptor sig | Falcon-512 descriptor co-sig (mandatory when present) |
| `.moor` address commitment | — | BLAKE2b-16(ML-KEM_pk ‖ Falcon_pk) |
| Consensus signatures | Ed25519 | ML-DSA-65 (sequential-AND verify) |
| Hashing / KDF | BLAKE2b-256, HKDF-BLAKE2b | — |

Classical crypto from libsodium. Post-quantum primitives are vendored NIST reference implementations from PQClean — no liboqs. PQ hybrid is mandatory; there is no downgrade path.

## Pluggable transports

| Transport | Technique | Looks like |
|-----------|-----------|------------|
| **ShitStorm** | Chrome 146 JA4, Elligator2, ECH GREASE, HTTP/2 | Chrome browsing |
| **Nether** | Minecraft 1.21.4 protocol, real handshake + login | Minecraft gameplay |
| **Mirage** | TLS 1.3 camouflage with real X25519 DH, configurable SNI | HTTPS to any domain |
| **Shade** | Elligator2 key obfuscation + IAT modes | Random bytes |
| **Scramble** | ASCII HTTP prefix + ChaCha20 payload | HTTP traffic |
| **Speakeasy** | SSH banner exchange + encrypted channel framing | SSH session |

Non-bridge relays trap DPI probes on their ORPort with a rotating set of fake industrial-control banners.

## Default network

| Node | Role | Address | Location |
|------|------|---------|----------|
| DA1 | Directory Authority | 107.174.70.38:9030 | US |
| DA2 | Directory Authority | 107.174.70.122:9030 | US |
| TURBINE | Relay | 104.129.51.133:9001 | US |
| DROPOUT | Guard relay | 86.54.28.132:9001 | NL |
| VALIDATOR | Exit relay | 86.54.28.49:9001 | NL |

## Documentation

- [Configuration](configuration.md) — all config options, CLI flags, relay types, exit policy
- [Architecture](architecture.md) — system design, source layout, cell format
- [Protocol](protocol.md) — wire formats, cell commands, handshakes, consensus format
- [Building](building.md) — dependencies, build options, cross-compilation, sanitizers
- [Security](security.md) — threat model, cryptographic analysis, limitations
- [OPSEC](opsec.md) — how to use MOOR without defeating the point
- [Philosophy](philosophy.md) — why MOOR exists
- [PQ crypto flow diagram](pq-crypto-flow.svg) — one-page overview

Website: <https://moor.afflicted.sh>
