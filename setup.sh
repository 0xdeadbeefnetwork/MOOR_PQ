#!/bin/bash
# MOOR Relay Setup
# One command to fetch, build, configure, and start a MOOR relay.
#
# Usage:
#   curl -sL https://raw.githubusercontent.com/0xdeadbeefnetwork/MOOR_PQ/main/setup.sh | sudo bash
#
# Or non-interactive:
#   curl -sL .../setup.sh | sudo bash -s -- --role exit --nickname MYRELAY --ip 1.2.3.4

set -euo pipefail

REPO_URL="https://github.com/0xdeadbeefnetwork/MOOR_PQ"
ROLE=""
NICKNAME=""
ADVERTISE=""
OR_PORT="9001"
CONF_DIR="/etc/moor"
DATA_DIR="/var/lib/moor"
BUILD_DIR="/opt/moor"
MOOR_USER="moor"

die() { echo "ERROR: $*" >&2; exit 1; }

detect_ip() {
    curl -4s --max-time 5 https://ifconfig.me 2>/dev/null ||
    curl -4s --max-time 5 https://icanhazip.com 2>/dev/null ||
    curl -4s --max-time 5 https://api.ipify.org 2>/dev/null ||
    echo ""
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --role)     ROLE="$2"; shift 2 ;;
        --nickname) NICKNAME="$2"; shift 2 ;;
        --ip)       ADVERTISE="$2"; shift 2 ;;
        --port)     OR_PORT="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: sudo $0 [--role exit|middle|guard|relay] [--nickname NAME] [--ip ADDR] [--port PORT]"
            exit 0 ;;
        *) die "Unknown option: $1" ;;
    esac
done

[[ "$(id -u)" -eq 0 ]] || die "Run with: curl -sL .../setup.sh | sudo bash"

cat << 'BANNER'

  __  __  ___   ___  ___
 |  \/  |/ _ \ / _ \|  _ \
 | |\/| | | | | | | | |_) |
 | |  | | |_| | |_| |  _ <
 |_|  |_|\___/ \___/|_| \_\

 Post-Quantum Anonymous Relay Setup

BANNER

# ---- interactive prompts ----

if [[ -z "$ROLE" ]]; then
    echo " What kind of node do you want to run?"
    echo ""
    echo "   1) relay     - General relay, DA assigns flags based on performance"
    echo "   2) middle    - Middle-only relay (never guard or exit)"
    echo "   3) exit      - Exit relay (forwards traffic to the internet)"
    echo "   4) guard     - Guard relay (entry point for circuits)"
    echo ""
    read -rp " Choose [1-4] (default: 1): " choice
    case "${choice:-1}" in
        1|relay)  ROLE="relay" ;;
        2|middle) ROLE="middle" ;;
        3|exit)   ROLE="exit" ;;
        4|guard)  ROLE="guard" ;;
        *) die "Invalid choice." ;;
    esac
fi

if [[ -z "$NICKNAME" ]]; then
    echo ""
    read -rp " Relay nickname: " NICKNAME
    [[ -n "$NICKNAME" ]] || die "Nickname required."
fi
# Sanitize nickname (alphanumeric + underscore only)
NICKNAME=$(echo "$NICKNAME" | tr -cd 'A-Za-z0-9_')
[[ -n "$NICKNAME" ]] || die "Nickname must contain at least one alphanumeric character."

if [[ -z "$ADVERTISE" ]]; then
    echo ""
    echo -n " Detecting public IP... "
    ADVERTISE=$(detect_ip)
    if [[ -n "$ADVERTISE" ]]; then
        echo "$ADVERTISE"
        read -rp " Use this IP? [Y/n]: " yn
        if [[ "${yn:-y}" =~ ^[Nn] ]]; then
            read -rp " Enter your public IP: " ADVERTISE
        fi
    else
        echo "couldn't detect"
        read -rp " Enter your public IP: " ADVERTISE
    fi
    [[ -n "$ADVERTISE" ]] || die "Public IP required."
fi

echo ""
read -rp " Contact info (email/URL, optional, press Enter to skip): " CONTACT_INFO

echo ""
echo " ----------------------------------------"
echo "  Role:     $ROLE"
echo "  Nickname: $NICKNAME"
echo "  Address:  $ADVERTISE:$OR_PORT"
if [[ -n "${CONTACT_INFO:-}" ]]; then
echo "  Contact:  $CONTACT_INFO"
fi
echo " ----------------------------------------"
echo ""
read -rp " Look good? [Y/n]: " confirm
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

# Check libsodium >= 1.0.18
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
./configure >/dev/null 2>&1
make -j"$(nproc)" >/dev/null 2>&1 || die "Build failed. Check: make -C $BUILD_DIR"
install -m 755 moor /usr/local/bin/moor
echo "  installed /usr/local/bin/moor"

# ---- configure ----

echo "[4/5] Configuring..."

# Create system user
if ! id "$MOOR_USER" &>/dev/null; then
    useradd -r -m -d /home/$MOOR_USER -s /usr/sbin/nologin "$MOOR_USER"
fi

mkdir -p "$DATA_DIR" "$CONF_DIR"
chown "$MOOR_USER:$MOOR_USER" "$DATA_DIR"

# Build role config line
ROLE_LINE=""
case "$ROLE" in
    relay)  ;; # no extra flag, DA decides
    middle) ROLE_LINE="MiddleOnly 1" ;;
    exit)   ROLE_LINE="Exit 1" ;;
    guard)  ROLE_LINE="Guard 1" ;;
esac

cat > "$CONF_DIR/moor.conf" << EOF
# MOOR Relay Configuration
# Generated $(date -u +%Y-%m-%d) by setup.sh
# Edit and restart: sudo systemctl restart moor

Mode relay
ORPort $OR_PORT
BindAddress 0.0.0.0
AdvertiseAddress $ADVERTISE
Nickname $NICKNAME
DataDirectory $DATA_DIR
${ROLE_LINE}
Verbose 1
$(if [[ -n "${CONTACT_INFO:-}" ]]; then echo "ContactInfo $CONTACT_INFO"; fi)

# Directory authorities (default MOOR network)
DAAddress 107.174.70.38
DAPort 9030

# Bandwidth (auto-detected, uncomment to override)
#BandwidthRate 10000000

# Exit policy (only applies to exit relays)
ExitPolicy reject *:25
ExitPolicy reject *:135-139
ExitPolicy reject *:445
ExitPolicy reject *:6881-6999
#ExitPolicy reject *:6881-6999
#ExitPolicy accept *:*
EOF

echo "  wrote $CONF_DIR/moor.conf"

# ---- systemd + start ----

echo "[5/5] Starting..."

cat > /etc/systemd/system/moor.service << EOF
[Unit]
Description=MOOR Relay ($NICKNAME)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$MOOR_USER
ExecStart=/usr/local/bin/moor --config $CONF_DIR/moor.conf
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

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
    echo "  MOOR relay is live!"
    echo " ========================================"
    echo ""
    echo "  $NICKNAME ($ROLE) @ $ADVERTISE:$OR_PORT"
    echo ""
    echo "  Config:   sudo nano $CONF_DIR/moor.conf"
    echo "  Logs:     journalctl -u moor -f"
    echo "  Restart:  sudo systemctl restart moor"
    echo "  Stop:     sudo systemctl stop moor"
    echo ""
else
    echo ""
    echo " Relay failed to start. Check:"
    echo "   journalctl -u moor --no-pager -n 30"
    exit 1
fi
