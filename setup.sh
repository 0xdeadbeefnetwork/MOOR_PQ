#!/bin/bash
# MOOR Relay Setup v0.8.1
# One command to fetch, build, configure, and start a MOOR node.
#
# Usage:
#   curl -sL https://moor.afflicted.sh/install.sh | sudo bash
#
# Non-interactive:
#   curl -sL .../install.sh | sudo bash -s -- --role exit --nickname MYRELAY --ip 1.2.3.4
#   curl -sL .../install.sh | sudo bash -s -- --role bridge --nickname MYBRIDGE --ip 1.2.3.4 --transport shitstorm
#   curl -sL .../install.sh | sudo bash -s -- --role relay --enclave /path/to/mynet.enclave

main() {

set -euo pipefail

if [[ ! -t 0 ]]; then
    exec 3</dev/tty || { echo "Error: cannot read from terminal (use --role/--nickname flags for non-interactive)"; exit 1; }
    STDIN_FD=3
else
    STDIN_FD=0
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

die() { echo "ERROR: $*" >&2; exit 1; }

detect_ip() {
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
        --help|-h)
            echo "Usage: sudo $0 [OPTIONS]"
            echo ""
            echo "  --role <type>       relay|middle|exit|guard|bridge"
            echo "  --nickname <name>   Node nickname"
            echo "  --ip <addr>         Public IP address"
            echo "  --port <port>       OR port (default: 9001)"
            echo "  --transport <name>  Bridge transport: shitstorm|mirage|shade|scramble|speakeasy"
            echo "  --enclave <file>    Use independent network (enclave file with DA list)"
            echo "  --contact <info>    Contact email/URL (optional)"
            exit 0 ;;
        *) die "Unknown option: $1" ;;
    esac
done

[[ "$(id -u)" -eq 0 ]] || die "Run with: curl -sL .../install.sh | sudo bash"

cat << 'BANNER'

  __  __  ___   ___  ___
 |  \/  |/ _ \ / _ \|  _ \
 | |\/| | | | | | | | |_) |
 | |  | | |_| | |_| |  _ <
 |_|  |_|\___/ \___/|_| \_\

 Post-Quantum Anonymous Network — v0.8.1

BANNER

# ---- interactive prompts ----

if [[ -z "$ROLE" ]]; then
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

if [[ "$ROLE" == "bridge" && -z "$TRANSPORT" ]]; then
    echo ""
    echo " Which pluggable transport?"
    echo ""
    echo "   1) shitstorm  - Chrome TLS 1.3 fingerprint (recommended, hardest to block)"
    echo "   2) mirage     - TLS 1.3 record framing with configurable SNI"
    echo "   3) shade      - Elligator2 statistical evasion"
    echo "   4) scramble   - Entropy evasion with HTTP prefix"
    echo "   5) speakeasy  - SSH protocol camouflage"
    echo ""
    read -rp " Choose [1-5] (default: 1): " tchoice <&$STDIN_FD
    case "${tchoice:-1}" in
        1|shitstorm) TRANSPORT="shitstorm" ;;
        2|mirage)    TRANSPORT="mirage" ;;
        3|shade)     TRANSPORT="shade" ;;
        4|scramble)  TRANSPORT="scramble" ;;
        5|speakeasy) TRANSPORT="speakeasy" ;;
        *) die "Invalid transport." ;;
    esac
fi

if [[ -z "$NICKNAME" ]]; then
    echo ""
    read -rp " Node nickname: " NICKNAME <&$STDIN_FD
    [[ -n "$NICKNAME" ]] || die "Nickname required."
fi
NICKNAME=$(echo "$NICKNAME" | tr -cd 'A-Za-z0-9_')
[[ -n "$NICKNAME" ]] || die "Nickname must contain at least one alphanumeric character."

if [[ -z "$ADVERTISE" ]]; then
    echo ""
    echo -n " Detecting public IP... "
    ADVERTISE=$(detect_ip)
    if [[ -n "$ADVERTISE" ]]; then
        echo "$ADVERTISE"
        read -rp " Use this IP? [Y/n]: " yn <&$STDIN_FD
        if [[ "${yn:-y}" =~ ^[Nn] ]]; then
            read -rp " Enter your public IP: " ADVERTISE <&$STDIN_FD
        fi
    else
        echo "couldn't detect"
        read -rp " Enter your public IP: " ADVERTISE <&$STDIN_FD
    fi
    [[ -n "$ADVERTISE" ]] || die "Public IP required."
fi

if [[ -z "$CONTACT_INFO" ]]; then
    echo ""
    read -rp " Contact info (email/URL, optional, press Enter to skip): " CONTACT_INFO <&$STDIN_FD
fi

# Ask about enclave if not specified
if [[ -z "$ENCLAVE" ]]; then
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
read -rp " Look good? [Y/n]: " confirm <&$STDIN_FD
[[ "${confirm:-y}" =~ ^[Yy]|^$ ]] || { echo " Aborted."; exit 0; }

# ---- install dependencies ----

echo ""
echo "[1/5] Installing dependencies..."
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq build-essential libsodium-dev zlib1g-dev pkg-config git curl >/dev/null 2>&1
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q gcc make libsodium-devel zlib-devel pkg-config git curl >/dev/null 2>&1
elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm base-devel libsodium zlib git curl >/dev/null 2>&1
elif command -v apk >/dev/null 2>&1; then
    apk add --quiet build-base libsodium-dev zlib-dev pkgconfig git curl
else
    die "Unsupported OS. Install manually: gcc make libsodium-dev zlib1g-dev pkg-config git"
fi

if pkg-config --exists libsodium 2>/dev/null; then
    SODIUM_VER=$(pkg-config --modversion libsodium)
    if [[ "$(printf '%s\n' "1.0.18" "$SODIUM_VER" | sort -V | head -1)" != "1.0.18" ]]; then
        echo "  libsodium $SODIUM_VER too old, building 1.0.20 from source..."
        cd /tmp
        curl -sLO https://download.libsodium.org/libsodium/releases/libsodium-1.0.20-RELEASE.tar.gz
        tar xzf libsodium-1.0.20-RELEASE.tar.gz
        cd libsodium-1.0.20-RELEASE
        ./configure --prefix=/usr/local >/dev/null 2>&1
        make -j"$(nproc)" >/dev/null 2>&1 && make install >/dev/null 2>&1
        ldconfig
        cd /tmp && rm -rf libsodium-1.0.20-RELEASE*
    fi
else
    die "libsodium not found after install."
fi
echo "  done"

# ---- fetch source ----

echo "[2/5] Fetching source..."
rm -rf "$BUILD_DIR"
git clone --depth 1 "$REPO_URL" "$BUILD_DIR" 2>/dev/null ||
    die "Failed to clone $REPO_URL"
echo "  done"

# ---- build ----

echo "[3/5] Building moor..."
cd "$BUILD_DIR"
chmod +x configure 2>/dev/null
if ! ./configure > /tmp/moor_build.log 2>&1; then
    echo "  configure failed:"
    tail -5 /tmp/moor_build.log
    die "Run manually: cd $BUILD_DIR && ./configure && make"
fi
if ! make -j"$(nproc)" >> /tmp/moor_build.log 2>&1; then
    echo "  build failed:"
    tail -10 /tmp/moor_build.log
    die "Run manually: cd $BUILD_DIR && make"
fi
install -m 755 moor /usr/local/bin/moor
echo "  installed /usr/local/bin/moor"

# ---- configure ----

echo "[4/5] Configuring..."

if ! id "$MOOR_USER" &>/dev/null; then
    useradd -r -m -d /home/$MOOR_USER -s /usr/sbin/nologin "$MOOR_USER"
fi

mkdir -p "$DATA_DIR" "$CONF_DIR"
chown "$MOOR_USER:$MOOR_USER" "$DATA_DIR"

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
Verbose 1
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
