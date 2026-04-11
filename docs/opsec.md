# Operational Security

How to run MOOR without defeating the point of running MOOR.

## Client

**Do not run MOOR and then log into your real identity.** The exit relay sees your traffic in the clear (for HTTP) or sees the destination (for HTTPS). If you log into Gmail through MOOR, your ISP can't see it, but Google knows it's you.

**Use HTTPS everywhere.** MOOR encrypts between you and the exit relay. Between the exit relay and the destination, it's the open internet. HTTPS protects that last mile.

**Do not torrent through MOOR.** BitTorrent leaks your real IP in tracker announces and DHT, even when proxied through SOCKS5. It also kills network performance for everyone.

**DNS matters.** Always use `socks5h://` (not `socks5://`). The `h` means hostname resolution happens through the network. Without it, your OS resolves DNS directly, leaking every domain you visit to your ISP.

**Browser fingerprinting is real.** Your browser leaks screen resolution, installed fonts, timezone, language, WebGL renderer, and hundreds of other signals. MOOR anonymizes your IP, not your browser. Use a hardened browser or Tor Browser (configured to use MOOR's SOCKS port).

**Do not resize the browser window.** Unique window dimensions are a fingerprint.

**Disable JavaScript when possible.** JS can extract timing data, canvas fingerprints, and WebRTC leaks that deanonymize you regardless of the network layer.

**Do not open downloaded files while connected.** PDFs, Office documents, and other file types can phone home to embedded URLs, bypassing the proxy.

## Relay operator

**Use a VPS, not your home connection.** Your ISP and anyone watching your home IP will see sustained encrypted connections to other MOOR relays. A VPS provides network-level separation.

**Exit relays will receive abuse complaints.** Exit traffic appears to originate from your IP. Have a plan: use a hosting provider that understands anonymous relay operation, and maintain an exit notice page explaining what the relay does.

**Separate your relay identity from your real identity.** Pay for hosting with privacy-preserving methods. Do not register the VPS under your real name if you want operational separation.

**Keep the system updated.** MOOR is one process on the machine. If the OS is compromised, MOOR's crypto is irrelevant.

**Monitor your relay.** Watch for unusual resource usage. Set up unattended-upgrades. Rotate keys if you suspect compromise.

**Run a middle relay if you want low risk.** Middle relays never see client IPs or destination traffic. They just forward encrypted cells. Abuse complaints go to exit operators, not middle operators.

## Hidden service operator

**The .moor address IS your identity.** Anyone who knows it can connect. Share it only through channels you trust.

**Your local service must not leak information.** The web server behind the hidden service should not include headers that reveal the real hostname, server software version, or internal IPs. Strip `Server:`, `X-Powered-By:`, and similar headers.

**Do not serve the same content on the clearnet and the hidden service.** Content correlation is a trivial deanonymization technique.

**Clock skew can deanonymize.** If your HS publishes descriptors at predictable intervals relative to your timezone, an adversary can narrow down your location. MOOR uses epoch-aligned consensus intervals, but your local service's behavior (log timestamps, cron jobs) may still leak timing.

**Vanguards help but are not bulletproof.** MOOR uses vanguard relays to protect hidden service circuits from guard discovery attacks. With only 3 relays in the network, vanguard diversity is limited. More relays improve this.

**Client authorization limits exposure.** Use `HiddenServiceAuthorizedClient` to restrict who can even fetch your descriptor. Unauthorized users cannot discover that the service exists.

## General

**Anonymity is a spectrum, not a switch.** MOOR provides network-layer anonymity. It routes your traffic through 3 hops so no single point knows both who you are and what you're doing. It does not make you invisible.

**Your threat model matters.** MOOR protects against your ISP, the coffee shop WiFi, and a passive network observer. It does not protect against a global adversary who can watch all links simultaneously, or against an adversary who has compromised your machine.

**Post-quantum protects the future, not the past.** Traffic recorded before you started using MOOR is not retroactively protected. PQ hybrid means traffic recorded today cannot be decrypted by a future quantum computer.

**Metadata is data.** Even if an adversary cannot read your traffic, they can see that you are using MOOR (unless you use pluggable transports). The fact that you use an anonymity network is itself information.

**Pluggable transports hide that you're using MOOR.** ShitStorm makes traffic look like Chrome. Nether makes it look like Minecraft. Mirage looks like TLS 1.3. Shade looks like random noise. Speakeasy looks like SSH. Scramble looks like HTTP. Use them in environments where MOOR traffic might be blocked or flagged.

**Do not be the only user.** Anonymity requires a crowd. A network with one user provides no anonymity. The more people use MOOR, the stronger everyone's anonymity becomes.
