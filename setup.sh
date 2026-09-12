#!/bin/bash
# MOOR Relay Setup v0.8.1
# One command to build, configure, and start a MOOR node -- from the checkout
# it is run in. What you read is what gets installed.
#
# Usage (from a clone you have looked at):
#   git clone https://github.com/0xdeadbeefnetwork/MOOR_PQ && cd MOOR_PQ
#   sudo ./setup.sh
#
# Non-interactive:
#   sudo ./setup.sh --role exit --nickname MYRELAY --ip 1.2.3.4
#   sudo ./setup.sh --role bridge --nickname MYBRIDGE --ip 1.2.3.4 --transport shitstorm
#   sudo ./setup.sh --role relay --enclave /path/to/mynet.enclave
#
# Pinned fetch, when there is no checkout on the box:
#   sudo ./setup.sh --fetch <full 40-hex commit id> [--repo URL]
#
# Piping this file from a URL into a root shell is not supported any more:
# that installed whatever upstream HEAD was at that moment (review finding
# F-16). --fetch takes a commit id, never a branch or tag, and refuses any
# tree that does not resolve to exactly that commit.

main() {

set -euo pipefail

# Detect if we can prompt the user. Three cases:
#   1. Interactive terminal (./setup.sh) → stdin works
#   2. No stdin but a tty (sudo under some terminals) → /dev/tty works
#   3. Piped without tty (ssh remote sudo) → no prompts, flags required
STDIN_FD=0
if [[ ! -t 0 ]]; then
    STDIN_FD=""
    if (: </dev/tty) 2>/dev/null; then
        exec 3</dev/tty
        STDIN_FD=3
    fi
fi

REPO_URL="https://github.com/0xdeadbeefnetwork/MOOR_PQ"
ROLE=""
NICKNAME=""
ADVERTISE=""
OR_PORT="9001"
CONF_DIR="/etc/moor"
DATA_DIR="/var/lib/moor"
BUILD_DIR="/opt/moor"
MOOR_USER="moor"
TRANSPORT=""
ENCLAVE=""
CONTACT_INFO=""
FETCH_COMMIT=""

die() { echo "ERROR: $*" >&2; exit 1; }

detect_ip() {
    # F-24: these third parties learn this machine's public IP. Harmless for a
    # relay whose address is about to be published anyway, but a privacy tool
    # should say so rather than do it quietly. --ip skips this entirely.
    curl -4s --max-time 5 https://ifconfig.me 2>/dev/null ||
    curl -4s --max-time 5 https://icanhazip.com 2>/dev/null ||
    curl -4s --max-time 5 https://api.ipify.org 2>/dev/null ||
    echo ""
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --role)      ROLE="$2"; shift 2 ;;
        --nickname)  NICKNAME="$2"; shift 2 ;;
        --ip)        ADVERTISE="$2"; shift 2 ;;
        --port)      OR_PORT="$2"; shift 2 ;;
        --transport) TRANSPORT="$2"; shift 2 ;;
        --enclave)   ENCLAVE="$2"; shift 2 ;;
        --contact)   CONTACT_INFO="$2"; shift 2 ;;
        --fetch)     FETCH_COMMIT="$2"; shift 2 ;;
        --repo)      REPO_URL="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: sudo $0 [OPTIONS]"
            echo ""
            echo "  --role <type>       relay|middle|exit|guard|bridge"
            echo "  --nickname <name>   Node nickname"
            echo "  --ip <addr>         Public IP address"
            echo "  --port <port>       OR port (default: 9001)"
            echo "  --transport <name>  Bridge transport: shitstorm|mirage|shade|scramble|speakeasy|nether"
            echo "  --enclave <file>    Use independent network (enclave file with DA list)"
            echo "  --contact <info>    Contact email/URL (optional)"
            exit 0 ;;
        *) die "Unknown option: $1" ;;
    esac
done

[[ "$(id -u)" -eq 0 ]] || die "Run with: sudo ./setup.sh"

cat << 'BANNER'

  __  __  ___   ___  ___
 |  \/  |/ _ \ / _ \|  _ \
 | |\/| | | | | | | | |_) |
 | |  | | |_| | |_| |  _ <
 |_|  |_|\___/ \___/|_| \_\

 Post-Quantum Anonymous Network — v0.8.1

BANNER

# ---- interactive prompts (skipped if all required args provided) ----

# Helper: prompt only if we have a terminal
ask() {
    local var="$1" prompt="$2" default="${3:-}"
    if [[ -n "$STDIN_FD" ]]; then
        read -rp "$prompt" "$var" <&$STDIN_FD
    elif [[ -n "$default" ]]; then
        # F-25: printf %q quotes the value so a default containing a single
        # quote cannot break out of the assignment.
        eval "$var=$(printf '%q' "$default")"
    else
        die "$var is required (no terminal for prompt — pass via flags)"
    fi
}

if [[ -z "$ROLE" ]]; then
    if [[ -z "$STDIN_FD" ]]; then
        ROLE="relay"  # default when non-interactive
    else
        echo " What kind of node do you want to run?"
        echo ""
        echo "   1) relay     - General relay, DA assigns flags based on performance"
        echo "   2) middle    - Middle-only relay (never guard or exit)"
        echo "   3) exit      - Exit relay (forwards traffic to the internet)"
        echo "   4) guard     - Guard relay (entry point for circuits)"
        echo "   5) bridge    - Bridge relay (unlisted, censorship circumvention)"
        echo ""
        read -rp " Choose [1-5] (default: 1): " choice <&$STDIN_FD
        case "${choice:-1}" in
            1|relay)  ROLE="relay" ;;
            2|middle) ROLE="middle" ;;
            3|exit)   ROLE="exit" ;;
            4|guard)  ROLE="guard" ;;
            5|bridge) ROLE="bridge" ;;
            *) die "Invalid choice." ;;
        esac
    fi
fi

if [[ "$ROLE" == "bridge" && -z "$TRANSPORT" ]]; then
    if [[ -z "$STDIN_FD" ]]; then
        TRANSPORT="shitstorm"
    else
        echo ""
        echo " Which pluggable transport?"
        echo ""
        echo "   1) shitstorm  - Chrome TLS 1.3 fingerprint (recommended, hardest to block)"
        echo "   2) nether     - Minecraft protocol camouflage"
        echo "   3) mirage     - TLS 1.3 record framing with configurable SNI"
        echo "   4) shade      - Elligator2 statistical evasion"
        echo "   5) scramble   - Entropy evasion with HTTP prefix"
        echo "   6) speakeasy  - SSH protocol camouflage"
        echo ""
        read -rp " Choose [1-6] (default: 1): " tchoice <&$STDIN_FD
        case "${tchoice:-1}" in
            1|shitstorm) TRANSPORT="shitstorm" ;;
            2|nether)    TRANSPORT="nether" ;;
            3|mirage)    TRANSPORT="mirage" ;;
            4|shade)     TRANSPORT="shade" ;;
            5|scramble)  TRANSPORT="scramble" ;;
            6|speakeasy) TRANSPORT="speakeasy" ;;
            *) die "Invalid transport." ;;
        esac
    fi
fi

if [[ -z "$NICKNAME" ]]; then
    ask NICKNAME " Node nickname: "
fi
NICKNAME=$(echo "$NICKNAME" | tr -cd 'A-Za-z0-9_')
[[ -n "$NICKNAME" ]] || die "Nickname must contain at least one alphanumeric character."

if [[ -z "$ADVERTISE" ]]; then
    echo ""
    echo -n " Detecting public IP... "
    ADVERTISE=$(detect_ip)
    if [[ -n "$ADVERTISE" ]]; then
        echo "$ADVERTISE"
        if [[ -n "$STDIN_FD" ]]; then
            read -rp " Use this IP? [Y/n]: " yn <&$STDIN_FD
            if [[ "${yn:-y}" =~ ^[Nn] ]]; then
                read -rp " Enter your public IP: " ADVERTISE <&$STDIN_FD
            fi
        fi
    else
        echo "couldn't detect"
        ask ADVERTISE " Enter your public IP: "
    fi
    [[ -n "$ADVERTISE" ]] || die "Public IP required."
fi

if [[ -n "$STDIN_FD" && -z "$CONTACT_INFO" ]]; then
    echo ""
    read -rp " Contact info (email/URL, optional, press Enter to skip): " CONTACT_INFO <&$STDIN_FD
fi

# Ask about enclave only interactively
if [[ -n "$STDIN_FD" && -z "$ENCLAVE" ]]; then
    echo ""
    read -rp " Use an enclave file? (path, or Enter for default network): " ENCLAVE <&$STDIN_FD
fi

echo ""
echo " ----------------------------------------"
echo "  Role:      $ROLE"
echo "  Nickname:  $NICKNAME"
echo "  Address:   $ADVERTISE:$OR_PORT"
[[ -n "$TRANSPORT" ]]    && echo "  Transport: $TRANSPORT"
[[ -n "$ENCLAVE" ]]      && echo "  Enclave:   $ENCLAVE"
[[ -n "$CONTACT_INFO" ]] && echo "  Contact:   $CONTACT_INFO"
echo " ----------------------------------------"
echo ""
if [[ -n "$STDIN_FD" ]]; then
    read -rp " Look good? [Y/n]: " confirm <&$STDIN_FD
    [[ "${confirm:-y}" =~ ^[Yy]|^$ ]] || { echo " Aborted."; exit 0; }
fi

# ---- install dependencies ----

echo ""
echo "[1/5] Installing dependencies..."
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq build-essential libsodium-dev libevent-dev zlib1g-dev pkg-config git curl >/dev/null 2>&1
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q gcc make libsodium-devel libevent-devel zlib-devel pkg-config git curl >/dev/null 2>&1
elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm base-devel libsodium libevent zlib git curl >/dev/null 2>&1
elif command -v apk >/dev/null 2>&1; then
    apk add --quiet build-base libsodium-dev libevent-dev zlib-dev pkgconfig git curl
else
    die "Unsupported OS. Install manually: gcc make libsodium-dev libevent-dev zlib1g-dev pkg-config git"
fi

if pkg-config --exists libsodium 2>/dev/null; then
    SODIUM_VER=$(pkg-config --modversion libsodium)
    if [[ "$(printf '%s\n' "1.0.18" "$SODIUM_VER" | sort -V | head -1)" != "1.0.18" ]]; then
        echo "  libsodium $SODIUM_VER too old, building 1.0.20 from source..."
        cd /tmp
        # F-16: this used to download a libsodium tarball over plain HTTPS
        # with no signature or checksum check and build it as root -- the
        # shortest path from a compromised mirror or DNS answer to every
        # relay's identity key. libsodium publishes minisign signatures; none
        # were checked.
        #
        # It is also dead: that URL now returns 404, so the fallback has been
        # silently broken as well as unverified.
        #
        # Rather than pin a checksum this script cannot establish, refuse.
        # Installing a crypto library is the operator's decision to make
        # deliberately, from a source they trust, not something an install
        # script should do for them unverified.
        die "libsodium is not available from this system's package manager.
  Install it deliberately before re-running, either from your distribution or
  from source you have verified yourself:

    https://doc.libsodium.org/installation

  Verify the release signature with minisign against libsodium's published
  public key. This script will not download and build a crypto library
  unverified as root."
    fi
else
    die "libsodium not found after install."
fi
echo "  done"

# ---- source ----
# The tree this script sits in is the tree that gets built. The only fetch
# left is --fetch COMMIT, and it refuses anything but that exact commit.
SRC_DIR=""
if [[ -n "${BASH_SOURCE[0]:-}" && -f "$(dirname "${BASH_SOURCE[0]}")/src/main.c" ]]; then
    SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

if [[ -n "$FETCH_COMMIT" ]]; then
    [[ "$FETCH_COMMIT" =~ ^[0-9a-f]{40}$ ]] ||
        die "--fetch needs the full 40-hex commit id, not a branch or tag -- that is what makes it a pin"
    echo "[2/5] Fetching $REPO_URL at $FETCH_COMMIT..."
    rm -rf "$BUILD_DIR"
    git clone -q "$REPO_URL" "$BUILD_DIR" 2>/dev/null || die "Failed to clone $REPO_URL"
    git -C "$BUILD_DIR" checkout -q "$FETCH_COMMIT" 2>/dev/null ||
        die "$FETCH_COMMIT is not a commit in $REPO_URL"
    [[ "$(git -C "$BUILD_DIR" rev-parse HEAD)" == "$FETCH_COMMIT" ]] ||
        die "checked-out tree is not $FETCH_COMMIT -- refusing to build it"
    echo "  done"
elif [[ -n "$SRC_DIR" ]]; then
    echo "[2/5] Using source tree $SRC_DIR (commit $(git -C "$SRC_DIR" rev-parse --short HEAD 2>/dev/null || echo 'unknown, not a git checkout'))..."
    if [[ "$SRC_DIR" != "$BUILD_DIR" ]]; then
        rm -rf "$BUILD_DIR"
        cp -a "$SRC_DIR" "$BUILD_DIR"
    fi
    echo "  done"
else
    die "run this from a MOOR_PQ checkout (git clone it, read it, then: sudo ./setup.sh), or pass --fetch <full commit id>. Piping setup.sh from a URL is not supported."
fi

# ---- build ----

echo "[3/5] Building moor..."
cd "$BUILD_DIR"
chmod +x configure 2>/dev/null
if ! ./configure > /tmp/moor_build.log 2>&1; then
    echo "  configure failed:"
    tail -5 /tmp/moor_build.log
    die "Run manually: cd $BUILD_DIR && ./configure && make"
fi
# `make release` is the deployable binary: debug info split into moor.debug
# rather than shipped inside a 4 MB relay. The symbols go where gdb looks for
# a debuglink of an installed binary, so a crash off a live relay is readable.
if ! make -j"$(nproc)" release >> /tmp/moor_build.log 2>&1; then
    echo "  build failed:"
    tail -10 /tmp/moor_build.log
    die "Run manually: cd $BUILD_DIR && make release"
fi
install -m 755 moor /usr/local/bin/moor
install -d /usr/lib/debug/usr/local/bin
install -m 644 moor.debug /usr/lib/debug/usr/local/bin/moor.debug
echo "  installed /usr/local/bin/moor ($(stat -c %s moor) bytes; symbols in /usr/lib/debug/usr/local/bin/moor.debug)"

# GeoIP database for country diversity (Tor-format, IPFire location data).
# Tor stopped shipping src/config/geoip in its repo on 2024-03-05, so the old
# raw-GitHub fetch has 404'd on every fresh relay since. Take the files from
# the distro instead: apt checks the package against its keyring, and
# `apt-get download` + `dpkg -x` gives the two files without installing the
# tor daemon that tor-geoipdb depends on. Other distros ship the same files in
# their tor package; use them when present. Nothing is fetched over bare curl.
# moor looks in $GEOIP_DIR on its own (src/main.c), so no config line is needed.
GEOIP_DIR="/usr/local/share/moor"
mkdir -p "$GEOIP_DIR"
if [[ ! -s "$GEOIP_DIR/geoip" ]]; then
    geoip_src=""
    geoip_tmp=""
    if command -v apt-get >/dev/null 2>&1; then
        geoip_tmp=$(mktemp -d)
        if (cd "$geoip_tmp" && apt-get download tor-geoipdb >/dev/null 2>&1) &&
           dpkg -x "$geoip_tmp"/tor-geoipdb_*.deb "$geoip_tmp/x" 2>/dev/null &&
           [[ -s "$geoip_tmp/x/usr/share/tor/geoip" ]]; then
            geoip_src="$geoip_tmp/x/usr/share/tor"
        fi
    elif [[ -s /usr/share/tor/geoip ]]; then
        geoip_src=/usr/share/tor
    fi
    if [[ -n "$geoip_src" ]]; then
        install -m 644 "$geoip_src/geoip" "$GEOIP_DIR/geoip"
        [[ -s "$geoip_src/geoip6" ]] && install -m 644 "$geoip_src/geoip6" "$GEOIP_DIR/geoip6"
        echo "  installed GeoIP from the distro package ($(grep -vc '^#' "$GEOIP_DIR/geoip") entries)"
    else
        echo "  no GeoIP database available: country diversity is off (family diversity still applies)."
        echo "  Put a Tor-format geoip file at $GEOIP_DIR/geoip to enable it."
    fi
    [[ -n "$geoip_tmp" ]] && rm -rf "$geoip_tmp"
fi

# ---- configure ----

echo "[4/5] Configuring..."

if ! id "$MOOR_USER" &>/dev/null; then
    useradd -r -m -d /home/$MOOR_USER -s /usr/sbin/nologin "$MOOR_USER"
fi

mkdir -p "$DATA_DIR/keys" "$CONF_DIR"
chown -R "$MOOR_USER:$MOOR_USER" "$DATA_DIR"
chmod 700 "$DATA_DIR/keys"

# Build config
ROLE_LINE=""
BRIDGE_LINES=""
ENCLAVE_LINE=""
case "$ROLE" in
    relay)  ;;
    middle) ROLE_LINE="MiddleOnly 1" ;;
    exit)   ROLE_LINE="Exit 1" ;;
    guard)  ROLE_LINE="Guard 1" ;;
    bridge)
        BRIDGE_LINES="# Bridge configuration
IsBridge 1
BridgeTransport ${TRANSPORT:-shitstorm}"
        ;;
esac

if [[ -n "$ENCLAVE" && -f "$ENCLAVE" ]]; then
    cp "$ENCLAVE" "$CONF_DIR/network.enclave"
    chown "$MOOR_USER:$MOOR_USER" "$CONF_DIR/network.enclave"
    ENCLAVE_LINE="Enclave $CONF_DIR/network.enclave"
fi

cat > "$CONF_DIR/moor.conf" << EOF
# MOOR Node Configuration
# Generated $(date -u +%Y-%m-%d) by setup.sh v0.8.1

Mode relay
ORPort $OR_PORT
BindAddress 0.0.0.0
AdvertiseAddress $ADVERTISE
Nickname $NICKNAME
DataDirectory $DATA_DIR
${ROLE_LINE}
${BRIDGE_LINES}
${ENCLAVE_LINE}
$(if [[ -n "$CONTACT_INFO" ]]; then echo "ContactInfo $CONTACT_INFO"; fi)

# Bandwidth (auto-detected, uncomment to override)
#BandwidthRate 10000000

# Exit policy (only applies to exit relays)
ExitPolicy reject *:25
ExitPolicy reject *:135-139
ExitPolicy reject *:445
ExitPolicy reject *:6881-6999
EOF

# Clean up empty lines from unset variables
sed -i '/^$/d' "$CONF_DIR/moor.conf"

echo "  wrote $CONF_DIR/moor.conf"

# ---- systemd + start ----

echo "[5/5] Starting..."

cat > /etc/systemd/system/moor.service << EOF
[Unit]
Description=MOOR Node ($NICKNAME)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$MOOR_USER
ExecStart=/usr/local/bin/moor --config $CONF_DIR/moor.conf
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
LimitCORE=infinity

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable moor --quiet
systemctl restart moor

sleep 3

if systemctl is-active --quiet moor; then
    echo ""
    echo " ========================================"
    echo "  MOOR node is live!"
    echo " ========================================"
    echo ""
    echo "  $NICKNAME ($ROLE) @ $ADVERTISE:$OR_PORT"
    if [[ "$ROLE" == "bridge" ]]; then
        echo ""
        echo "  Bridge transport: $TRANSPORT"
        echo "  Bridge line will appear in: journalctl -u moor | grep 'bridge line'"
        echo "  Give the bridge line to users who need censorship circumvention."
    fi
    if [[ -n "$ENCLAVE_LINE" ]]; then
        echo "  Network: custom enclave ($CONF_DIR/network.enclave)"
    else
        echo "  Network: default MOOR network"
    fi
    echo ""
    echo "  Config:   sudo nano $CONF_DIR/moor.conf"
    echo "  Logs:     journalctl -u moor -f"
    echo "  Restart:  sudo systemctl restart moor"
    echo "  Stop:     sudo systemctl stop moor"
    echo ""
else
    echo ""
    echo " Node failed to start. Check:"
    echo "   journalctl -u moor --no-pager -n 30"
    exit 1
fi

} # end main()
main "$@"
