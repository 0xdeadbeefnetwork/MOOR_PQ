# MOOR

Post-quantum anonymous overlay network. 3-hop onion routing with hybrid X25519 + Kyber768 at every layer.

## What it does

MOOR routes your traffic through 3 encrypted relays so no single point can see both who you are and what you're accessing.

```
You  --->  Guard  --->  Middle  --->  Exit  --->  Internet
           sees         sees          sees
           your IP      nothing       destination
```

- **Guard** — entry relay. Knows your IP, not your destination.
- **Middle** — passes encrypted data. Sees nothing useful.
- **Exit** — connects to the destination. Does not know your IP.

## Modes

MOOR is a single binary that runs as:

- **Client** — SOCKS5 proxy on localhost, routes traffic through the network
- **Relay** — forwards encrypted cells (guard, middle, or exit)
- **Directory Authority (DA)** — publishes signed relay list with Ed25519 + ML-DSA-65 dual signatures
- **Hidden Service** — hosts a `.moor` service reachable only through the network
- **OnionBalance** — load-balances a hidden service across backends
- **BridgeDB** — distributes bridge addresses to censored users
- **Bridge Authority** — manages bridge relay consensus

## Quick start

```
make
./moor                              # client: SOCKS5 on port 9050
```

Deploy a relay (one command):
```
curl -sL https://raw.githubusercontent.com/0xdeadbeefnetwork/MOOR_PQ/main/setup.sh | sudo bash
```

Deploy a relay (manual):
```
./moor --mode relay --advertise YOUR_IP --nickname MYRELAY -v
./moor --mode relay --advertise YOUR_IP --nickname MYRELAY --exit -v
./moor --mode relay --advertise YOUR_IP --nickname MYRELAY --guard -v
```

Hidden service:
```
./moor --mode hs --hs-port 8080 -v
```

Browse through MOOR:
```
curl -x socks5h://127.0.0.1:9050 http://example.com
```

Connect through a bridge:
```
./moor --UseBridges 1 --Bridge "shitstorm 1.2.3.4:9001 <fingerprint>" -v
```

## Relay types

| Type | Flag | What it does | What it sees | Risk |
|------|------|-------------|-------------|------|
| Relay | (none) | General purpose, DA assigns role by performance | Depends | Low |
| Middle | `--middle-only` | Only middle hop, never guard or exit | Nothing useful | Lowest |
| Guard | `--guard` | Entry point for client circuits | Client IPs, not destinations | Low |
| Exit | `--exit` | Forwards traffic to the internet | Destinations, not client IPs | Gets abuse complaints |

Under 20 relays: self-declared flags trusted immediately. Over 20: guards must earn it (Fast + Stable + bandwidth + 8 days uptime). Exit is always opt-in.

## Crypto

| Layer | Algorithm | Post-Quantum |
|-------|-----------|-------------|
| Link handshake | Noise_IK (X25519 + ChaCha20-Poly1305 + BLAKE2b) | + Kyber768 |
| Circuit key exchange | X25519 Diffie-Hellman | + Kyber768 KEM |
| Cell encryption | ChaCha20 stream cipher | keys are PQ-derived |
| Consensus signatures | Ed25519 | + ML-DSA-65 (Dilithium3) |
| Hashing | BLAKE2b-256 | -- |

Classical crypto via libsodium. PQ crypto via vendored NIST reference implementations.

## Pluggable transports

| Transport | Technique | Blocks |
|-----------|-----------|--------|
| ShitStorm | Chrome 130 TLS 1.3 + Elligator2 + HTTP/2 framing | DPI, protocol fingerprinting |
| Scramble | ASCII HTTP prefix + ChaCha20 payload | Entropy-based filters |
| Shade | Elligator2 key obfuscation + IAT modes | Statistical classifiers |
| Mirage | TLS 1.3 camouflage with real x25519 DH | Protocol identification |
| WebWTF | WebRTC video call (STUN+DTLS+SRTP) | (in design) |

## Network

| Node | Role | Address | Location |
|------|------|---------|----------|
| VALIDATOR | Exit relay | 86.54.28.49:9001 | NL |
| DROPOUT | Guard relay | 86.54.28.132:9001 | NL |
| TURBINE | Middle relay | 104.129.51.133:9001 | US |
| DA1 | Directory Authority | 107.174.70.38:9030 | US |
| DA2 | Directory Authority | 107.174.70.122:9030 | US |

## Documentation

- [Configuration](configuration.md) — all config options, CLI flags, relay types, exit policy
- [Architecture](architecture.md) — system design, source layout, browsing walkthrough, cell format
- [Protocol](protocol.md) — wire formats, cell commands, handshakes, consensus format
- [Building](building.md) — dependencies, build options, cross-compilation, sanitizers
- [Security](security.md) — threat model, crypto analysis, limitations
- [OPSEC](opsec.md) — how to use MOOR without defeating the point
- [Philosophy](philosophy.md) — why MOOR exists
- [WebWTF Design](webwtf-design.md) — UDP WebRTC transport design document

Website: [https://moor.afflicted.sh](https://moor.afflicted.sh)
