# MOOR

Post-quantum anonymous overlay network. Version 0.8.0.

## What is this?

MOOR is a tool that makes your internet traffic anonymous. When you normally browse the web, every website you visit can see your IP address (your internet "home address"), and your internet provider can see every website you visit. MOOR fixes both problems.

It works using a technique called **onion routing**. Think of it like sending a letter inside multiple sealed envelopes. You give the letter to a chain of three couriers. Each courier can only open one envelope, which tells them who to hand it to next -- but none of them can read the actual letter, and none of them know the full route.

In technical terms: your traffic is encrypted in three layers and passed through three relays. Each relay peels off one layer of encryption, learns only the next step, and forwards the data. No single relay ever knows both who you are and what you are accessing.

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

- **Guard** (entry relay): Knows your IP address because you connect to it directly. Does NOT know what website you are visiting because that information is still encrypted under two more layers.
- **Middle** relay: Knows nothing useful. It receives encrypted data from the guard and passes it to the exit. It cannot see your IP address or your destination.
- **Exit** relay: Connects to the website on your behalf. It can see the destination (e.g., "example.com") but does NOT know your IP address -- it only knows the middle relay handed it the data.

This split means an attacker would have to control all three relays at the same time to figure out both who you are and what you are doing.

### Post-quantum cryptography

Everything in MOOR uses **hybrid encryption**: every key exchange combines a classical algorithm (X25519) with a post-quantum algorithm (Kyber768). An attacker must break BOTH to decrypt anything. This means that even if a powerful quantum computer is built in the future, traffic recorded today stays protected.

## Quick start

### Run as a client (browse anonymously)

```
# Install dependencies (Debian/Ubuntu)
sudo apt install build-essential libsodium-dev zlib1g-dev pkg-config

# Build
./configure
make

# Run (starts a SOCKS5 proxy on port 9050)
./moor

# Browse through MOOR
curl -x socks5h://127.0.0.1:9050 http://example.com
```

Point any application that supports SOCKS5 proxies at `127.0.0.1:9050`. Use `socks5h://` (with the `h`) so that domain name lookups also go through the network -- without the `h`, your computer resolves DNS directly and your ISP can see which sites you visit.

### Run a relay (help the network)

The easiest way to set up a relay is the automated setup script. It installs dependencies, builds MOOR from source, creates a system service, and starts your relay:

```
curl -sL https://raw.githubusercontent.com/0xdeadbeefnetwork/MOOR_PQ/main/setup.sh | sudo bash
```

The script will ask you to choose a role, pick a nickname, and confirm your public IP. You can also run it non-interactively:

```
curl -sL https://raw.githubusercontent.com/0xdeadbeefnetwork/MOOR_PQ/main/setup.sh | \
  sudo bash -s -- --role exit --nickname MYRELAY --ip 1.2.3.4
```

Or set up manually:

```
./moor --mode relay --advertise 1.2.3.4 --nickname MYRELAY -v         # general relay
./moor --mode relay --exit --advertise 1.2.3.4 --nickname MYRELAY -v  # exit relay
./moor --mode relay --guard --advertise 1.2.3.4 --nickname MYRELAY -v # guard relay
```

See [docs/configuration.md](docs/configuration.md) for all options.

### Run a hidden service

Host a service reachable only through the MOOR network at a `.moor` address:

```
# Start a hidden service that proxies to a local web server on port 8080
./moor --mode hs --hs-dir ./hs_keys --hs-port 8080 -v

# Your .moor address is printed on startup and saved to hs_keys/hostname
```

Clients connect via SOCKS5:

```
curl -x socks5h://127.0.0.1:9050 http://your-address-here.moor/
```

The hidden service uses a 6-hop tunnel (3 client + 3 service) with PQ hybrid end-to-end encryption (X25519 + Kyber768). The rendezvous relay that bridges both sides sees only ciphertext. Vanguard relays protect the service from guard discovery attacks. Proof-of-work prevents introduction flooding.

## Cryptography

| Layer | Algorithm | What it protects |
|-------|-----------|-----------------|
| Link handshake | Noise_IK (X25519 + ChaCha20 + BLAKE2b) + Kyber768 | Connection between you and the first relay |
| Circuit key exchange | X25519 + Kyber768 hybrid | Each hop of the 3-hop path |
| HS e2e encryption | X25519 + Kyber768 hybrid (post-handshake KEM upgrade) | End-to-end between client and hidden service |
| Onion encryption | ChaCha20 stream cipher (keys derived from PQ hybrid exchange) | Data in transit through the circuit |
| Consensus signatures | Ed25519 + ML-DSA-65 (Dilithium3) | Integrity of the relay directory |
| Hashing | BLAKE2b-256 | Internal integrity checks |
| Identity keys | Ed25519 | Relay and service identity |
| KEM | ML-KEM-768 (Kyber768) | Post-quantum key encapsulation (NIST Level 3) |
| PQ Signatures | ML-DSA-65 (Dilithium3) | Post-quantum signature verification (NIST Level 3) |

Every layer -- link, circuit, and hidden service end-to-end -- uses hybrid PQ cryptography. An attacker must break both X25519 and Kyber768 to decrypt anything, at any layer. All classical crypto via libsodium (audited, constant-time). PQ crypto via vendored NIST reference implementations.

## Current network

| Node | Role | IP | Location |
|------|------|----|----------|
| DA1 | Directory Authority | 107.174.70.38 | US |
| DA2 | Directory Authority | 107.174.70.122 | US |
| TURBINE | Middle relay | 104.129.51.133 | US |
| DROPOUT | Guard relay | 86.54.28.132 | NL |
| VALIDATOR | Exit relay | 86.54.28.49 | NL |

The directory authorities maintain a signed list of all relays in the network. Clients download this list to choose their 3-hop paths.

## Documentation

- [Overview and docs index](docs/README.md)
- [Philosophy](docs/philosophy.md) -- Why MOOR exists, design principles, the cypherpunk tradition
- [Architecture](docs/architecture.md) -- System design, source layout, data flow
- [Configuration](docs/configuration.md) -- All config options, CLI flags, relay types explained
- [Building](docs/building.md) -- Build instructions, dependencies, setup script
- [Protocol](docs/protocol.md) -- Wire formats, cell types, consensus document format
- [Security](docs/security.md) -- Threat model, crypto analysis, known limitations
- [OPSEC](docs/opsec.md) -- How to use MOOR without defeating the point of using MOOR

## Source

https://github.com/0xdeadbeefnetwork/MOOR_PQ

## License

See LICENSE file.
