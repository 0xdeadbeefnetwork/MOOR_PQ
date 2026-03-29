# MOOR

Anonymous overlay network. 3-hop onion routing with post-quantum cryptography.

## What it does

MOOR routes your internet traffic through 3 encrypted relays so that no single point can see both who you are and what you're accessing. Every hop uses X25519 + Kyber768 hybrid key exchange -- a quantum computer would need to break both to decrypt anything.

```
You  --->  Guard  --->  Middle  --->  Exit  --->  Internet
           sees         sees          sees
           your IP      nothing       destination
```

- **Guard** -- entry relay. Knows your IP, doesn't know your destination.
- **Middle** -- just passes encrypted data. Sees nothing useful.
- **Exit** -- connects to the destination. Doesn't know your IP.

## Modes

MOOR is a single binary that runs as:

- **Client** -- SOCKS5 proxy on localhost, routes traffic through the network
- **Relay** -- forwards encrypted cells (guard, middle, or exit)
- **Directory Authority (DA)** -- publishes a signed list of known relays
- **Hidden Service** -- hosts a service reachable only through the network (.moor addresses)
- **OnionBalance** -- load-balances a hidden service across multiple backends
- **BridgeDB** -- distributes bridge addresses to censored users
- **Bridge Authority** -- manages a separate consensus of bridge relays

## Quick start

```
./configure && make
./moor                              # client: SOCKS5 on port 9050
```

Run a relay (easiest):
```
curl -sL https://raw.githubusercontent.com/0xdeadbeefnetwork/MOOR_PQ/main/setup.sh | sudo bash
```

Run a relay (manual):
```
./moor --mode relay --advertise YOUR_IP --nickname MYRELAY -v           # general relay
./moor --mode relay --advertise YOUR_IP --nickname MYRELAY --exit -v    # exit relay
./moor --mode relay --advertise YOUR_IP --nickname MYRELAY --guard -v   # guard relay
```

Hidden service:
```
./moor --mode hs --hs-port 8080 -v
```

Browse through MOOR:
```
curl -x socks5h://127.0.0.1:9050 http://example.com
```

## Relay types

| Type | Flag | What it does | What it sees | Risk |
|------|------|-------------|-------------|------|
| Relay | (none) | General purpose, DA assigns role based on performance | Depends | Low |
| Middle | `--middle-only` | Only ever middle hop, never guard or exit | Nothing useful | Lowest |
| Guard | `--guard` | Entry point for client circuits | Client IPs, not destinations | Low |
| Exit | `--exit` | Forwards traffic to the internet | Destinations, not client IPs | Gets abuse complaints |

Under 20 relays in the network, self-declared flags are trusted immediately. Over 20, guards must earn it (Fast + Stable + bandwidth + 8 days uptime). Nobody accidentally becomes an exit -- exit is always opt-in.

## Crypto

| Layer | Algorithm | Post-Quantum |
|-------|-----------|-------------|
| Link handshake | Noise_IK (X25519 + ChaCha20-Poly1305 + BLAKE2b) | + Kyber768 |
| Circuit key exchange (all 3 hops) | X25519 Diffie-Hellman | + Kyber768 KEM |
| Cell encryption | ChaCha20 stream cipher | keys are PQ-derived |
| Consensus signatures | Ed25519 | + ML-DSA-65 (Dilithium3) |
| Hashing | BLAKE2b-256 | -- |

Classical crypto via libsodium. PQ crypto via vendored NIST reference implementations.

## Network

| Node | Role | Address | Location |
|------|------|---------|----------|
| VALIDATOR | Exit relay | 86.54.28.49:9001 | NL |
| DROPOUT | Guard relay | 86.54.28.132:9001 | NL |
| TURBINE | Middle relay | 104.129.51.133:9001 | US |
| DA1 | Directory Authority | 107.174.70.38:9030 | US |
| DA2 | Directory Authority | 107.174.70.122:9030 | US |

Live metrics: [DA1](http://107.174.70.38:9030) | [DA2](http://107.174.70.122:9030)

## Documentation

- [Configuration](configuration.md) -- All config options, CLI flags, relay types
- [Architecture](architecture.md) -- System design, source layout, data flow
- [Protocol](protocol.md) -- Wire formats, cell types, consensus format
- [Building](building.md) -- Dependencies, build options, cross-compilation
- [Security](security.md) -- Threat model, crypto analysis, limitations
- [OPSEC](opsec.md) -- How to use MOOR without defeating the point
- [Philosophy](philosophy.md) -- Why MOOR exists

Website: [https://moor.afflicted.sh](https://moor.afflicted.sh)
