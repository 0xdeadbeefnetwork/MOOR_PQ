# Configuration

MOOR is configured via a config file (`-f moorrc` or `--config moorrc`) or CLI
flags. CLI flags override config-file values. With no arguments, MOOR starts as
a SOCKS5 client on `127.0.0.1:9050`.

Config file format: one `Key Value` pair per line. Lines starting with `#` are
comments.

```
# Example moorrc
SocksPort 9050
Verbose 1
```

---

## Client

A client connects to the MOOR network and exposes a local SOCKS5 proxy.
Applications route traffic through the proxy to reach destinations anonymously.

**Minimal usage:**

```bash
./moor                           # SOCKS5 proxy on 127.0.0.1:9050
```

**Explicit options:**

```bash
./moor --socks-port 9150 --bind 127.0.0.1 --pir -v
```

| CLI Flag | Config Key | Default | Description |
|----------|-----------|---------|-------------|
| `--socks-port <port>` | `SocksPort` | 9050 | SOCKS5 proxy listen port |
| `--bind <addr>` | `BindAddress` | 127.0.0.1 | Address to bind listeners on |
| `--da-address <addr>` | `DAAddress` | 107.174.70.38 | Directory authority address (comma-separated for multiple) |
| `--da-port <port>` | `DAPort` | 9030 | Directory authority port |
| `--data-dir <dir>` | `DataDir` / `DataDirectory` | ~/.moor | Persistent state directory (guard state, consensus cache) |
| `--pir` / `--no-pir` | `PIR` | 1 (on) | PIR for hidden-service descriptor lookups |
| `--geoip <file>` | `GeoIPFile` | | IPv4 GeoIP database (Tor-compatible format) |
| `--geoip6 <file>` | `GeoIPv6File` | | IPv6 GeoIP database (Tor-compatible format) |
| `--EntryNode <fp>` | `EntryNode` / `EntryNodes` | | Pin a specific entry relay by fingerprint |
| `-v` | `Verbose` | 0 | Verbose logging |
| `-f <file>` / `--config <file>` | | | Load config from file |
| `-h` / `--help` | | | Print usage and exit |

Requests for `.onion` addresses are rejected at the SOCKS5 ingress — MOOR
uses `.moor`, not `.onion`.

**Transparent proxy (gateway mode):**

| CLI Flag | Config Key | Default | Description |
|----------|-----------|---------|-------------|
| `--TransPort <port>` | `TransPort` | 0 (off) | Transparent TCP proxy port |
| | `TransListenAddress` | | Bind address for transparent proxy |
| `--DNSPort <port>` | `DNSPort` | 0 (off) | DNS resolver port for transparent proxying |
| | `DNSListenAddress` | | Bind address for DNS port |
| | `AutomapHostsOnResolve` | 0 | Map `.moor` hostnames to virtual IPs automatically |

**IPv6 options:**

| Config Key | Default | Description |
|-----------|---------|-------------|
| `ClientUseIPv6` | 0 | Allow connecting to relays over IPv6 |
| `ClientPreferIPv6ORPort` | 0 | Prefer IPv6 ORPorts when available |

**Client-side onion auth:**

| Config Key | Description |
|-----------|-------------|
| `ClientOnionAuthDir` | Directory containing `.auth_private` files for v3 onion client authentication |

---

## Relay

A relay forwards traffic for other MOOR users. The directory authority (DA)
assigns consensus flags based on relay performance. You choose what *role*
your relay plays.

### Relay types

| Type | How to set | What it does |
|------|-----------|--------------|
| **General relay** | `--mode relay` (no flags) | Forwards traffic within the network. The DA assigns Guard, Exit, or other flags based on performance and uptime. |
| **Guard** | `--guard` or `Guard 1` | Entry point for client circuits. Sees client IPs, not destinations. Self-declared; DAs can strip the flag on large networks if performance criteria are not met. |
| **Exit** | `--exit` or `Exit 1` / `ExitRelay 1` | Forwards traffic to the public internet. Self-declared — the DA always preserves this flag. Nobody accidentally becomes an exit. |
| **Middle-only** | `--middle-only` or `MiddleOnly 1` | Explicitly middle-only. DAs strip Guard, Exit, and HSDir flags from this relay. |
| **Bridge** | `--is-bridge` or `IsBridge 1` | Unlisted relay for censorship circumvention. Not published in the public consensus. |

### Flag assignment by the DA

DAs compute flags statistically across all registered relays. Each DA
independently computes flags from medians — there is no cross-DA majority
vote on flags.

| Flag | Criteria | Notes |
|------|----------|-------|
| **Fast** | Bandwidth ≥ 12.5th percentile (floor: 4 KB/s) | ~87.5% of relays get this |
| **Stable** | Uptime ≥ median uptime | ~50% of relays get this |
| **Guard** | Fast + Stable + bandwidth ≥ median non-exit bandwidth + time known ≥ 8 days | Under 20 relays: self-declared Guard is trusted immediately |
| **HSDir** | Fast + Stable + uptime ≥ 96 hours | Under 20 relays: uptime requirement waived |
| **Exit** | Relay self-declares `Exit 1` | DA always preserves this; never auto-assigned |
| **MiddleOnly** | Relay self-declares `MiddleOnly 1` | DA strips Guard, Exit, and HSDir |

### Relay configuration

**Example:**

```bash
./moor --mode relay --bind 0.0.0.0 --advertise 1.2.3.4 --guard --nickname MyRelay -v
```

**Config file:**

```
Mode relay
BindAddress 0.0.0.0
AdvertiseAddress 1.2.3.4
ORPort 9001
Guard 1
Nickname MyRelay
BandwidthRate 1000000
Verbose 1
```

| CLI Flag | Config Key | Default | Description |
|----------|-----------|---------|-------------|
| `--mode relay` | `Mode` | client | Run as relay |
| `--or-port <port>` / `--ORPort <port>` | `ORPort` | 9001 | Onion routing port (required for relay mode) |
| `--advertise <addr>` | `AdvertiseAddress` | auto-detected | Public IP address. Auto-detected via connected-UDP probe to the DA. Guard/exit relays fail startup if detection fails. |
| `--guard` | `Guard` | 0 | Advertise as guard relay |
| `--exit` / `--ExitRelay 1` | `Exit` / `ExitRelay` | 0 | Advertise as exit relay |
| `--middle-only` | `MiddleOnly` | 0 | Middle-only relay |
| `--nickname <name>` / `--Nickname <name>` | `Nickname` | | Human-readable relay name |
| `--bandwidth <bw>` / `--BandwidthRate <bw>` | `Bandwidth` / `BandwidthRate` | 1000000 | Advertised bandwidth in bytes/s |
| `--is-bridge` | `IsBridge` | 0 | Run as unlisted bridge relay |
| `--bridge-transport <t>` | | scramble | Bridge pluggable transport (see Transports below) |
| `--pow-difficulty <n>` | `PowDifficulty` | 0 | Argon2id proof-of-work difficulty for DA registration (0-64) |
| `--pow-memlimit <KB>` | `PowMemLimit` | 0 | Argon2id memory limit in KB |
| `--mix-delay <ms>` | `MixDelay` | 0 | Poisson mixing delay in milliseconds (0 = disabled) |
| `--exit-notice` | `ExitNotice` | 1 (on for exits) | Serve mandatory HTTP notice on :80 ("this is a MOOR exit, not a website") |
| `--dns-server-port <p>` | `DNSServerPort` | 0 (off) | DNS-over-TCP listener port, intended to sit behind a hidden service |
| `--dns-server-upstream <host[:p]>` | `DNSServerUpstream` | 91.239.100.100:53 | Upstream recursive resolver for DNS-over-TCP (default: UncensoredDNS, anycast, no logs/filtering) |

**Additional relay config-file options:**

| Config Key | Default | Description |
|-----------|---------|-------------|
| `RelayFamily` | | Ed25519 fingerprint (64 hex chars) of a sibling relay. Up to 8 entries. |
| `AccountingMax` | 0 (off) | Maximum bytes transferred per accounting period |
| `AccountingPeriod` | | Accounting period in seconds (required if AccountingMax is set) |
| `RateLimit` | 0 (off) | Rate limit in bytes/s |
| `DirCache` | 0 | Cache and serve directory data |
| `UseMicrodescriptors` | 0 | Use microdescriptors instead of full descriptors |

**Strict build-ID fleet gate.** Every node stamps a 16-byte git-hash build ID
into its descriptor. Directory authorities reject descriptors whose
`build_id` differs from their own — mixed-commit fleets cannot form. Upgrade
the whole fleet in lockstep when the build ID changes.

**Scanner honeypot.** Non-bridge relays intercept ORPort probes matching
well-known DPI fingerprints (HTTP `GET `, `SSH-2.0`, SCADA banners) and
return rotating fake industrial-control responses. Bridge relays skip this
so legitimate transport cover prefixes pass through.

### Finding your relay fingerprint

Your relay is identified by a 64-character hex Ed25519 fingerprint. Three
ways to retrieve it, in order of how lazy you are:

1. **System log on startup.** The relay prints a `relay fingerprint: <hex>`
   line right next to the `build <id>` banner. On a systemd box that lands
   in `journalctl -u moor` (or `/var/log/syslog` if you're on rsyslog).

2. **`moor --print-fingerprint`.** Reads only the public-key file
   (`<data-dir>/keys/identity_pk`), so it works without sudo if the file
   is world-readable. Defaults to `/var/lib/moor`:

   ```bash
   moor --print-fingerprint
   moor --print-fingerprint --data-dir /custom/path
   ```

3. **Web dashboard.** The DA's HTML dashboard at the DirPort lists every
   relay in the consensus. Each relay's identity column links through to
   `/relay.html?fp=<full-hex>` for a per-relay drilldown view, and there
   is a search box at the top of the relay table.

### Verifying your relay is reachable

`moor --check-relay` answers two different questions depending on what you
pass it:

```bash
# "Is the rest of the network seeing me?" -- queries a DA's /relay?fp= endpoint
# for consensus presence, then live-probes the consensus address.
moor --check-relay <64-hex-fingerprint>
moor --check-relay <fingerprint> <da_ip:da_port>   # specific DA

# "Is anything answering MOOR protocol at this socket?" -- direct PROBE/ALIVE
# roundtrip against the relay (same liveness handshake DAs use). No DA lookup.
moor --check-relay <addr>:<port>
```

Both forms exit non-zero on failure. The universe-mode form is the right
one for "did my relay actually integrate into the network?" — the local
form only proves something is answering at that socket.

---

## Directory authority

A directory authority (DA) maintains the network consensus — the
authoritative list of all relays and their flags. DAs exchange votes with
peers and produce a signed consensus document dual-signed Ed25519 +
ML-DSA-65 (sequential-AND verify on the client).

**Example:**

```bash
./moor --mode da --bind 0.0.0.0 --dir-port 9030 \
    --da-peers 1.2.3.4:9030:75655827bd8c9c68cf646a22936ea9f730dda8c955023ac0bfd05c62a1133cff -v
```

**Config file:**

```
Mode da
BindAddress 0.0.0.0
DirPort 9030
DAPeers 1.2.3.4:9030:75655827bd8c9c68cf646a22936ea9f730dda8c955023ac0bfd05c62a1133cff
Verbose 1
```

| CLI Flag | Config Key | Default | Description |
|----------|-----------|---------|-------------|
| `--mode da` | `Mode` | client | Run as directory authority |
| `--dir-port <port>` / `--DirPort <port>` | `DirPort` | 9030 | Directory service port (required for DA mode) |
| `--da-peers <list>` | `DAPeers` | | Peer DAs: `ip:port:hex_pk,...` (comma-separated) |

The `--da-peers` format includes each peer's Ed25519 identity fingerprint
(64 hex characters). Each DA prints its fingerprint at startup:

```
DA identity fingerprint: 75655827bd8c9c68cf646a22936ea9f730dda8c955023ac0bfd05c62a1133cff
```

Two DAs are hardcoded by default (107.174.70.38 and 107.174.70.122 with
embedded Ed25519 public keys). Additional DAs can be configured via
`DAAddress` with comma-separated entries:

```
DAAddress 107.174.70.38:9030,107.174.70.122:9030,10.0.0.5:9030
```

Up to 9 DAs are supported. Production-grade deployments should use 5-9 DAs
for Byzantine fault tolerance.

**Fallback directories:**

| Config Key | Description |
|-----------|-------------|
| `FallbackDir` | Fallback directory cache: `addr:port hex_fingerprint`. Up to 16 entries. |

---

## Hidden service

A hidden service exposes a local TCP service as a `.moor` onion address.
Keys are generated on first run and reused on subsequent runs.

**Example (config file recommended):**

```
Mode hs
DAAddress 107.174.70.38
DAPort 9030
HiddenServiceDir /var/lib/moor/hs_keys
HiddenServicePort 8080
Verbose 1
```

**CLI:**

```bash
./moor --mode hs --hs-dir /var/lib/moor/hs_keys --hs-port 8080 -v
```

| CLI Flag | Config Key | Default | Description |
|----------|-----------|---------|-------------|
| `--mode hs` | `Mode` | client | Run as hidden service |
| `--hs-dir <dir>` | `HiddenServiceDir` | ./hs_keys | Directory for HS key material (created if missing) |
| `--hs-port <port>` | `HiddenServicePort` | 8080 | Local port to forward incoming connections to |
| | `HiddenServiceAuthorizedClient` | | Base32-encoded Curve25519 public key for client authorization. Up to 16 per service. |

Multiple hidden services can be configured in one config file (up to 8).
Each `HiddenServiceDir` line starts a new service, and subsequent
`HiddenServicePort` and `HiddenServiceAuthorizedClient` lines apply to it:

```
HiddenServiceDir /var/lib/moor/hs_web
HiddenServicePort 80 8080
HiddenServiceAuthorizedClient aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

HiddenServiceDir /var/lib/moor/hs_ssh
HiddenServicePort 22
```

On first run, the HS generates:

- Ed25519 identity keypair
- Curve25519 onion keypair
- ML-KEM-768 encapsulation keypair
- Falcon-512 signing keypair

and writes the resulting `.moor` address to `HiddenServiceDir/hostname`.
The address is PQ-committed:
`base32(Ed25519_pk || BLAKE2b_16(ML-KEM_pk || Falcon_pk)).moor`. Swapping
either post-quantum key invalidates the address.

**HS proof-of-work (anti-DoS):**

| Config Key | Default | Description |
|-----------|---------|-------------|
| `HSPoW` | 0 | Enable proof-of-work for HS introduction |
| `HSPoWDifficulty` | 0 | PoW difficulty (0-64) |

**OnionBalance (load balancing):**

The `ob` mode runs an OnionBalance-style frontend that distributes traffic
across backend hidden service instances.

```
Mode ob
OnionBalanceMaster <master_address>
OnionBalancePort 8080
```

| Config Key | Description |
|-----------|-------------|
| `OnionBalanceMaster` | Master `.moor` address for the OnionBalance frontend |
| `OnionBalancePort` | Port the OnionBalance frontend listens on |

---

## Exit policy

Exit relays control which destinations they allow traffic to. Rules are
evaluated in order — first match wins. If no rule matches, traffic is
rejected (implicit `reject *:*`).

**Syntax:** `ExitPolicy <action> <address>:<port>`

- `<action>` is `accept` or `reject`
- `<address>` is an IPv4 address, IPv4 CIDR, IPv6 address (in brackets),
  IPv6 CIDR, or `*` for wildcard
- `<port>` is a single port, a port range (`80-443`), or `*` for all ports

**Example — web-only exit:**

```
ExitPolicy accept *:80
ExitPolicy accept *:443
ExitPolicy reject *:*
```

**Example — block a subnet:**

```
ExitPolicy reject 10.0.0.0/8:*
ExitPolicy reject [fc00::]/7:*
ExitPolicy accept *:*
```

**Default exit policy** (applied when no `ExitPolicy` lines are present and
the relay is an exit) rejects private/reserved ranges (RFC 1918, loopback,
link-local, CGNAT), blocks abuse-prone ports (SMTP 25/465/587, NNTP,
SMB/RPC, P2P file sharing), and accepts everything else. This mirrors
Tor's default exit policy.

Blocked port ranges in the default policy:

| Ports | Service |
|-------|---------|
| 25 | SMTP |
| 119 | NNTP |
| 135-139 | RPC/DCOM, NetBIOS |
| 445 | SMB |
| 465, 587 | SMTP Submission/SMTPS |
| 563 | NNTPS |
| 1214 | Kazaa |
| 4661-4666 | eMule |
| 6346-6429 | Gnutella |
| 6699 | Napster |
| 6881-6999 | BitTorrent |

Every exit relay also serves a **mandatory HTTP notice** on :80 explaining
it is a MOOR exit, not a web server (safe-harbor / mere-conduit posture).

---

## Bridges

Bridges are unlisted relays that help users in censored regions connect
to the MOOR network. Bridge addresses are not published in the public
consensus.

### Running a bridge

```bash
./moor --mode relay --bind 0.0.0.0 --is-bridge --bridge-transport shitstorm -v
```

| CLI Flag | Config Key | Default | Description |
|----------|-----------|---------|-------------|
| `--is-bridge` | `IsBridge` | 0 | Run as an unlisted bridge relay |
| `--bridge-transport <t>` | | scramble | Pluggable transport: `scramble`, `shade`, `mirage`, `shitstorm`, `speakeasy`, `nether` |

### Pluggable transports

Six cover-traffic transports are available. Pick one per bridge.

| Transport | Cover | Wire appearance |
|-----------|-------|-----------------|
| **ShitStorm** | Chrome 131+ JA4 (X25519MLKEM768 keyshare) + Elligator2 + ECH GREASE + HTTP/2 | Chrome browsing a CDN |
| **Nether** | Minecraft 1.21.4 handshake + login | Minecraft gameplay |
| **Mirage** | TLS 1.3 with real X25519 DH + configurable SNI | HTTPS to any domain |
| **Shade** | Elligator2 obfuscation + inter-arrival-time modes | Random bytes |
| **Scramble** | ASCII HTTP/1.1 GET prefix + ChaCha20 stream | HTTP traffic |
| **Speakeasy** | SSH-2.0 banner + KEX + encrypted channel framing | SSH session |

### Using bridges (client)

```bash
./moor --use-bridges --bridge "shitstorm 1.2.3.4:9001 a1b2c3d4e5f6...64hex"
```

| CLI Flag | Config Key | Default | Description |
|----------|-----------|---------|-------------|
| `--use-bridges` / `--UseBridges 1` | `UseBridges` | 0 | Connect via bridges instead of direct DA access |
| `--bridge <line>` / `--Bridge <line>` | `Bridge` | | Bridge line: `transport addr:port fingerprint` |

Bridge line format: `<transport> <address>:<port> <64-char-hex-fingerprint>`

Using `--bridge` automatically implies `--use-bridges`. Up to 8 bridges can
be configured.

**Config file example:**

```
UseBridges 1
Bridge shitstorm 198.51.100.1:443 a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
Bridge nether    203.0.113.5:25565 deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
```

### Bridge authority and BridgeDB

| Config Key | Default | Description |
|-----------|---------|-------------|
| `BridgeAuthPort` | 0 | Port for bridge authority service |
| `BridgeDBPort` | 0 | Port for BridgeDB distribution service |
| `BridgeDBFile` | | Path to BridgeDB state file |

These are activated with `--mode bridge_auth` and `--mode bridgedb`
respectively.

---

## Traffic analysis defenses

MOOR includes several mechanisms to resist traffic analysis.

### Circuit padding

Padding inserts cover traffic to obscure real traffic patterns. It is
enabled by default (mandatory baseline).

```bash
./moor --padding --padding-machine web --padding-mode constant
```

| CLI Flag | Config Key | Default | Description |
|----------|-----------|---------|-------------|
| `--padding` | `Padding` | 1 (on) | Enable circuit padding |
| `--padding-machine <m>` | `PaddingMachine` | generic | WTF-PAD machine: `web`, `stream`, `generic`, `none` |
| `--padding-mode <mode>` | `PaddingMode` | 0 (none) | Advanced padding modes (see below) |

`PaddingMode` accepts a string containing one or more of: `constant`,
`adaptive`, `jitter`, `all`, `none`.

| Mode | Bitmask | Description |
|------|---------|-------------|
| `constant` | 1 | Constant-rate cover traffic |
| `adaptive` | 2 | Adaptive burst cover |
| `jitter` | 4 | Jitter delay on real packets |
| `all` | 7 | All modes combined |
| `none` | 0 | No advanced padding (baseline padding still active if `Padding 1`) |

FRONT padding (Rayleigh-sampled burst cover over the first 5 seconds) and
volume padding (cells-per-circuit padded to the next power of two) are
applied automatically when `Padding 1`.

### Conflux (multi-path circuits)

Splits traffic across up to 4 circuit legs with Feistel PRP sequence
encoding and a reorder buffer. SKIPS RTT-adaptive scheduling picks the
lowest-latency leg at each send.

```bash
./moor --conflux --conflux-legs 3
```

| CLI Flag | Config Key | Default | Description |
|----------|-----------|---------|-------------|
| `--conflux` | `Conflux` | 0 | Enable multi-path circuits |
| `--conflux-legs <n>` | `ConfluxLegs` | 2 | Number of circuit legs (2-4, clamped) |

### Poisson mixing

Adds random delay to forwarded cells to decorrelate timing.

| CLI Flag | Config Key | Default | Description |
|----------|-----------|---------|-------------|
| `--mix-delay <ms>` | `MixDelay` | 0 | Mean delay in milliseconds (0 = disabled) |

---

## Advanced options

### GeoIP path diversity

MOOR uses Tor-compatible GeoIP files to enforce geographic diversity in
circuit paths. Clients avoid building circuits where two hops share the
same country or AS number.

```bash
./moor --geoip /usr/share/tor/geoip --geoip6 /usr/share/tor/geoip6
```

IPv4 format: `INTLOW,INTHIGH,CC` (decimal integers, comma-separated).
IPv6 format: `IPV6LOW,IPV6HIGH,CC` (standard notation, comma-separated).

A ~370 K-entry IPv4 database is vendored with MOOR. Additional databases
can be obtained from the Tor Project or IPFire Location database.

### Control port

A Tor-compatible control protocol interface for programmatic access.

```bash
./moor --control-port 9051
```

| CLI Flag | Config Key | Default | Description |
|----------|-----------|---------|-------------|
| `--control-port <port>` | `ControlPort` | 0 (off) | Control port for external tools |
| | `ControlPortPassword` | | Password for control port authentication |

### Monitoring

| CLI Flag | Config Key | Default | Description |
|----------|-----------|---------|-------------|
| `--monitor` | `Monitor` | 0 | Enable built-in monitoring/metrics |

### Post-quantum cryptography

Hybrid classical + post-quantum is **mandatory**. There is no flag to
disable PQ, no fallback to classical-only, and no downgrade path. The
legacy `PQHybrid` config key is accepted for compatibility but has no
effect — PQ is always on.

### Tor-compatible CLI aliases

Several flags match Tor's naming convention for users migrating from Tor:

| Tor-style flag | Maps to |
|---------------|---------|
| `--SocksPort <port>` | `SocksPort` |
| `--ORPort <port>` | `ORPort` |
| `--DirPort <port>` | `DirPort` |
| `--ExitRelay 1` | `Exit` |
| `--Nickname <name>` | `Nickname` |
| `--DataDirectory <dir>` | `DataDir` |
| `--BandwidthRate <bw>` | `Bandwidth` |
| `--UseBridges 1` | `UseBridges` |
| `--Bridge <line>` | `Bridge` |
| `--ContactInfo <info>` | `ContactInfo` |

---

## Daemon mode

Run MOOR as a background daemon. Using `--pid-file` automatically enables
daemon mode.

```bash
./moor --daemon --pid-file /var/run/moor.pid
```

| CLI Flag | Config Key | Default | Description |
|----------|-----------|---------|-------------|
| `--daemon` | `Daemon` | 0 | Fork to background |
| `--pid-file <path>` | `PidFile` | | Write PID to file (implies `--daemon`) |

**Systemd example:**

```ini
[Unit]
Description=MOOR Onion Router
After=network.target

[Service]
ExecStart=/usr/local/bin/moor -f /etc/moor/moorrc
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

---

## Complete config key reference

Every key accepted in a config file, listed alphabetically:

| Config Key | Type | Default | CLI Equivalent |
|-----------|------|---------|----------------|
| `AccountingMax` | bytes | 0 | |
| `AccountingPeriod` | seconds | 0 | |
| `AdvertiseAddress` | IP | auto | `--advertise` |
| `AutomapHostsOnResolve` | 0/1 | 0 | |
| `Bandwidth` / `BandwidthRate` | bytes/s | 1000000 | `--bandwidth` / `--BandwidthRate` |
| `BindAddress` | IP | 127.0.0.1 | `--bind` |
| `Bridge` | string | | `--bridge` / `--Bridge` |
| `BridgeAuthPort` | port | 0 | |
| `BridgeDBFile` | path | | |
| `BridgeDBPort` | port | 0 | |
| `ClientOnionAuthDir` | path | | |
| `ClientPreferIPv6ORPort` | 0/1 | 0 | |
| `ClientUseIPv6` | 0/1 | 0 | |
| `Conflux` | 0/1 | 0 | `--conflux` |
| `ConfluxLegs` | 2-4 | 2 | `--conflux-legs` |
| `ControlPort` | port | 0 | `--control-port` |
| `ControlPortPassword` | string | | |
| `DAAddress` | IP(s) | 107.174.70.38 | `--da-address` |
| `DAPort` | port | 9030 | `--da-port` |
| `DAPeers` | string | | `--da-peers` |
| `Daemon` | 0/1 | 0 | `--daemon` |
| `DataDir` / `DataDirectory` | path | ~/.moor | `--data-dir` / `--DataDirectory` |
| `DirCache` | 0/1 | 0 | |
| `DirPort` | port | 9030 | `--dir-port` / `--DirPort` |
| `DNSListenAddress` | IP | | |
| `DNSPort` | port | 0 | `--DNSPort` |
| `DNSServerPort` | port | 0 | `--dns-server-port` |
| `DNSServerUpstream` | host[:port] | 91.239.100.100:53 | `--dns-server-upstream` |
| `Enclave` | path | | `--enclave` |
| `EntryNode` / `EntryNodes` | fingerprint | | `--EntryNode` |
| `Exit` / `ExitRelay` | 0/1 | 0 | `--exit` / `--ExitRelay` |
| `ExitNotice` | 0/1 | 1 (exits) | `--exit-notice` |
| `ExitPolicy` | rule | | |
| `FallbackDir` | string | | |
| `GeoIPFile` | path | | `--geoip` |
| `GeoIPv6File` | path | | `--geoip6` |
| `Guard` | 0/1 | 0 | `--guard` |
| `HSPoW` | 0/1 | 0 | |
| `HSPoWDifficulty` | 0-64 | 0 | |
| `HiddenServiceAuthorizedClient` | base32 | | |
| `HiddenServiceDir` | path | ./hs_keys | `--hs-dir` |
| `HiddenServicePort` | port | 8080 | `--hs-port` |
| `IsBridge` | 0/1 | 0 | `--is-bridge` |
| `MiddleOnly` | 0/1 | 0 | `--middle-only` |
| `MixDelay` | ms | 0 | `--mix-delay` |
| `Mode` | string | client | `--mode` |
| `Monitor` | 0/1 | 0 | `--monitor` |
| `Nickname` | string | | `--nickname` / `--Nickname` |
| `OnionBalanceMaster` | string | | |
| `OnionBalancePort` | port | 0 | |
| `ORPort` | port | 9001 | `--or-port` / `--ORPort` |
| `PIR` | 0/1 | 1 | `--pir` / `--no-pir` |
| `Padding` | 0/1 | 1 | `--padding` |
| `PaddingMachine` | string | generic | `--padding-machine` |
| `PaddingMode` | string | 0 | `--padding-mode` |
| `PidFile` | path | | `--pid-file` |
| `PQHybrid` | (ignored) | always on | `--pq-hybrid` |
| `PowDifficulty` | 0-64 | 0 | `--pow-difficulty` |
| `PowMemLimit` | KB | 0 | `--pow-memlimit` |
| `RateLimit` | bytes/s | 0 | |
| `RelayFamily` | hex fp | | |
| `SocksPort` | port | 9050 | `--socks-port` / `--SocksPort` |
| `TransListenAddress` | IP | | |
| `TransPort` | port | 0 | `--TransPort` |
| `UseBridges` | 0/1 | 0 | `--use-bridges` / `--UseBridges` |
| `UseMicrodescriptors` | 0/1 | 0 | |
| `Verbose` | 0/1 | 0 | `-v` |

---

## Enclaves

An enclave is an independent MOOR network with its own directory
authorities. The `--enclave <file>` flag replaces the hardcoded DA list
entirely.

**Enclave file format** (one DA per line):

```
# mynetwork.enclave
1.2.3.4:9030 <hex_ed25519_pk>
5.6.7.8:9030 <hex_ed25519_pk>
[2001:db8::1]:9030 <hex_ed25519_pk>     # IPv6 with bracket notation
```

**Generate DA keys:**

```bash
moor --keygen-enclave --advertise 1.2.3.4 --data-dir /var/lib/moor
```

Generates Ed25519 + ML-DSA-65 + Curve25519 keys, prints the enclave file
line.
