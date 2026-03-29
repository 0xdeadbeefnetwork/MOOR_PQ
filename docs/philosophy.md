# Philosophy

## Why MOOR exists

Privacy is not a feature. It is the absence of surveillance. The default state of a letter is sealed. The default state of a conversation is unrecorded. The default state of network traffic should be unreadable, unattributable, and unlinkable.

That is not the world we live in. Every packet you send carries your IP address. Your ISP logs every connection. Governments compel providers to retain data. Intelligence agencies tap fiber optic cables at scale. The infrastructure of the internet was built for routing, not for privacy.

Tor proved that onion routing works. Millions of people use it daily to circumvent censorship, protect sources, conduct research without surveillance, and exercise the basic human right to think without being watched.

MOOR exists because Tor was built before quantum computers were a real threat. RSA-1024 keys from a decade ago are already weak. RSA-4096 will fall when large-scale quantum hardware arrives. Every Tor circuit ever built using classical-only key exchange is a stored ciphertext waiting to be opened.

MOOR is onion routing rebuilt with post-quantum cryptography from the ground up. Not bolted on. Not negotiated. Every key exchange, every hop, every signature -- hybrid classical and post-quantum by default. X25519 and Kyber768. Ed25519 and ML-DSA-65. If either algorithm holds, the traffic stays sealed.

## Design principles

**Quantum resistance is not optional.** There is no flag to disable PQ. There is no fallback to classical-only circuits. Every circuit uses hybrid key exchange. Every consensus carries dual signatures. An adversary recording traffic today gets nothing useful from a quantum computer tomorrow.

**Simple code over clever code.** MOOR is a single C binary. One file per subsystem. No build system generators, no autotools, no cmake. `make` and it builds. The entire source fits in your head if you try hard enough. Complexity is the enemy of security -- every line of code is a potential vulnerability.

**Tor's architecture is proven.** Three-hop circuits. Onion encryption. Directory authorities. SOCKS5 proxy interface. Guard persistence. Bandwidth-weighted relay selection. These are not arbitrary design choices -- they are the result of two decades of academic research, real-world deployment, and adversarial pressure. MOOR adopts the architecture and replaces the cryptography.

**No trusted third parties.** The network operates with a distributed set of directory authorities. No single DA can forge a consensus. No relay can see both ends of a circuit. No hidden service operator needs to trust the network with their location. The math does the work, not promises.

**Defense in depth.** Link encryption protects the connection. Circuit encryption protects the path. Onion encryption protects each hop independently. Padding resists traffic analysis. Vanguards protect hidden service circuits. GeoIP diversity prevents geographic correlation. Any single layer can fail and the others still provide protection.

## What MOOR is not

MOOR is not a VPN. A VPN is a pipe to a single server operated by a company that can see all your traffic and knows your identity. MOOR splits trust across 3 independent relays, none of which can see the full picture.

MOOR is not a magic cloak of invisibility. It is a tool. Used correctly, it provides strong network-layer anonymity. Used carelessly, it provides a false sense of security that is worse than no anonymity at all.

MOOR is not finished. The network is small. The code has not been audited. The protocol will evolve. What it is today is a foundation: the cryptographic primitives are right, the architecture is proven, and the post-quantum protection is real.

## On naming

MOOR: as dark as it gets.

A moor is an open, wild, treeless landscape. Exposed to the elements but vast enough to disappear in. You can see everything and nothing. The name has no acronym. It is not an abbreviation. It is what it is.

The test network directory authorities are DA1 and DA2, while the relays carry NSA TAO operation codenames -- TURBINE, DROPOUT, VALIDATOR. This is not an accident. The tools built to surveil are now the names of the machines that resist surveillance. There is a symmetry in that.

## On the cypherpunk tradition

Privacy is necessary for an open society in the electronic age. We cannot expect governments, corporations, or other large, faceless organizations to grant us privacy out of their beneficence.

We must defend our own privacy if we expect to have any. Cypherpunks write code. We know that someone has to write software to defend privacy, and we're going to write it.

MOOR is that code.
