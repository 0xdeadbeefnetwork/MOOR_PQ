#!/bin/bash
# deploy-debug.sh — Deploy instrumented MOOR to fleet with proper ordering.
#
# Deploy order (staggered, Tor-aligned):
#   1. Stop ALL nodes (prevent stale connections)
#   2. Build + upload to ALL nodes in parallel
#   3. Start DAs first (with peer identity keys)
#   4. Wait for DAs to produce consensus
#   5. Start relays (they register with DAs)
#   6. Verify all nodes running
#
# Usage: ./deploy-debug.sh [--asan]

set -euo pipefail

SSH_KEY="$HOME/.ssh/moor_deploy"
SSH_USER="moor"
SSH_OPTS="-i $SSH_KEY -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o BatchMode=yes"
REMOTE_SRC="/tmp/moor-deploy"
NODES_CONF="$(dirname "$0")/nodes.conf"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

USE_ASAN=0
[[ "${1:-}" == "--asan" ]] && USE_ASAN=1

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}[OK]${NC} $*"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $*"; }
info() { echo -e "  ${CYAN}[..]${NC} $*"; }

# Parse nodes.conf
declare -a NAMES HOSTS MODES FLAGS
while IFS= read -r line; do
    [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
    name=$(echo "$line" | awk '{print $1}')
    host=$(echo "$line" | awk '{print $2}')
    mode=$(echo "$line" | awk '{print $3}')
    flags=$(echo "$line" | awk '{$1=$2=$3=""; print $0}' | sed 's/^ *//')
    NAMES+=("$name")
    HOSTS+=("$host")
    MODES+=("$mode")
    FLAGS+=("$flags")
done < "$NODES_CONF"

NODE_COUNT=${#NAMES[@]}

# Separate DAs and relays
declare -a DA_INDICES RELAY_INDICES
for ((n=0; n<NODE_COUNT; n++)); do
    if [[ "${MODES[$n]}" == "da" ]]; then
        DA_INDICES+=("$n")
    else
        RELAY_INDICES+=("$n")
    fi
done

echo -e "${CYAN}MOOR Fleet Deploy — ${#DA_INDICES[@]} DAs + ${#RELAY_INDICES[@]} relays (staggered)${NC}"
[[ $USE_ASAN -eq 1 ]] && echo -e "${RED}WARNING: ASAN mode (~3x slower)${NC}"
echo ""

# ==== Phase 1: Build locally ====
echo -e "${YELLOW}==> Building...${NC}"
cd "$SCRIPT_DIR"
if [[ $USE_ASAN -eq 1 ]]; then
    make debug 2>&1 | tail -3
    BINARY="moor_debug"
else
    make moor 2>&1 | tail -3
    BINARY="moor"
fi
ok "Built $BINARY"

# ==== Phase 2: Package ====
echo -e "${YELLOW}==> Packaging...${NC}"
TARBALL="/tmp/moor-debug-deploy.tar.gz"
tar czf "$TARBALL" -C "$SCRIPT_DIR" \
    --exclude='.git' --exclude='obj' --exclude='obj_*' --exclude='*.o' \
    --exclude='./moor' --exclude='./moor_debug' --exclude='./moor_keygen' \
    --exclude='./moor-top' --exclude='promo' --exclude='*.mp3' \
    --exclude='tor-0.4.9.6' --exclude='tor-0.4.9.5' --exclude='asan_*' --exclude='tsan_*' \
    --exclude='fuzz' --exclude='deploy.sh' \
    .
ok "Source tarball: $(du -h "$TARBALL" | cut -f1)"

# ==== Phase 3: Stop nodes (rolling: relays first, then DAs one at a time) ====
echo -e "${YELLOW}==> Stopping relays...${NC}"
for idx in "${RELAY_INDICES[@]}"; do
    ssh $SSH_OPTS ${SSH_USER}@${HOSTS[$idx]} "sudo systemctl stop moor 2>/dev/null; sudo pkill -9 moor 2>/dev/null; true" &
done
wait
ok "Relays stopped"

echo -e "${YELLOW}==> Stopping DAs (one at a time)...${NC}"
for idx in "${DA_INDICES[@]}"; do
    ssh $SSH_OPTS ${SSH_USER}@${HOSTS[$idx]} "sudo systemctl stop moor 2>/dev/null; sudo pkill -9 moor 2>/dev/null; true"
    ok "${NAMES[$idx]} stopped"
done

# ==== Phase 4: Upload, build, install on ALL nodes in parallel ====
deploy_node() {
    local name="$1" host="$2"
    local BUILD_TARGET="moor"
    [[ $USE_ASAN -eq 1 ]] && BUILD_TARGET="debug"
    local INSTALL_BIN="moor"
    [[ $USE_ASAN -eq 1 ]] && INSTALL_BIN="moor_debug"

    # Install deps
    ssh $SSH_OPTS ${SSH_USER}@${host} bash -s <<'TOOLS_EOF' >/dev/null 2>&1
        export DEBIAN_FRONTEND=noninteractive
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update -qq 2>/dev/null
            sudo apt-get install -y -qq gdb strace libsodium-dev libevent-dev build-essential 2>/dev/null || true
        elif command -v yum >/dev/null 2>&1; then
            sudo yum install -y -q gdb strace libsodium-devel libevent-devel gcc make 2>/dev/null || true
        fi
TOOLS_EOF

    # System debug config
    ssh $SSH_OPTS ${SSH_USER}@${host} bash -s <<'SYSCONF_EOF' >/dev/null 2>&1
        echo '/tmp/core.%e.%p.%t' | sudo tee /proc/sys/kernel/core_pattern >/dev/null 2>/dev/null || true
        echo 'kernel.core_pattern=/tmp/core.%e.%p.%t' | sudo tee /etc/sysctl.d/99-moor-coredump.conf >/dev/null
        sudo sysctl -p /etc/sysctl.d/99-moor-coredump.conf 2>/dev/null || true
        echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope >/dev/null 2>/dev/null || true
SYSCONF_EOF

    # Upload
    ssh $SSH_OPTS ${SSH_USER}@${host} "rm -rf $REMOTE_SRC && mkdir -p $REMOTE_SRC" 2>/dev/null
    scp -i "$SSH_KEY" -o BatchMode=yes -q "$TARBALL" ${SSH_USER}@${host}:${REMOTE_SRC}/src.tar.gz

    # Build
    ssh $SSH_OPTS ${SSH_USER}@${host} bash -s "$BUILD_TARGET" <<'BUILDSSH' >/dev/null 2>&1
        set -e
        BUILD_TARGET="$1"
        cd /tmp/moor-deploy
        tar xzf src.tar.gz
        ./configure 2>&1 | tail -1
        make clean 2>/dev/null || true
        make -j$(nproc) $BUILD_TARGET 2>&1
BUILDSSH

    # Install (NEVER touch /var/lib/moor/keys — DA identity is permanent)
    ssh $SSH_OPTS ${SSH_USER}@${host} bash -s "$INSTALL_BIN" <<'INSTALLSSH' >/dev/null 2>&1
        set -e
        cd /tmp/moor-deploy
        sudo cp "$1" /usr/local/bin/moor
        sudo chmod 755 /usr/local/bin/moor
        sudo mkdir -p /usr/local/share/moor /var/lib/moor/keys
        # Verify existing keys are intact (refuse to deploy if corrupted)
        if [ -f /var/lib/moor/keys/identity_pk ]; then
            KEY_SIZE=$(stat -c%s /var/lib/moor/keys/identity_pk 2>/dev/null || echo 0)
            if [ "$KEY_SIZE" -ne 32 ]; then
                echo "FATAL: identity_pk is ${KEY_SIZE} bytes (expected 32) — refusing deploy"
                exit 1
            fi
        fi
        [ -f .gdbinit ] && sudo cp .gdbinit /usr/local/share/moor/gdbinit && cp .gdbinit ~/
INSTALLSSH

    echo "$name"
}

echo -e "${YELLOW}==> Building on all nodes (parallel)...${NC}"
for ((n=0; n<NODE_COUNT; n++)); do
    deploy_node "${NAMES[$n]}" "${HOSTS[$n]}" &
done
wait
ok "All nodes built and installed"

# ==== Phase 5: Load DA public keys from da-keys.conf ====
DA_KEYS_CONF="$(dirname "$0")/da-keys.conf"
echo -e "${YELLOW}==> Loading DA public keys from da-keys.conf...${NC}"
declare -A DA_KEYS
if [[ ! -f "$DA_KEYS_CONF" ]]; then
    fail "da-keys.conf not found! Create it with DA public keys."
    fail "Run on each DA: xxd -p -c32 /var/lib/moor/keys/identity_pk | head -1"
    exit 1
fi
while IFS= read -r line; do
    [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
    da_addr=$(echo "$line" | awk '{print $1}')
    da_pk=$(echo "$line" | awk '{print $2}')
    # Extract just the host (without port) for lookup
    da_host="${da_addr%%:*}"
    DA_KEYS[$da_host]="$da_pk"
    ok "$da_addr pk=${da_pk:0:16}..."
done < "$DA_KEYS_CONF"

# ==== Phase 6: Start DAs (rolling — one at a time with health gate) ====
echo -e "${YELLOW}==> Starting DAs (rolling restart with health checks)...${NC}"

# Health check: wait until DA is serving consensus
da_wait_healthy() {
    local host="$1" name="$2" max_wait=60
    local elapsed=0
    while [[ $elapsed -lt $max_wait ]]; do
        # DA dir port is 9030; check if it responds to CONSENSUS request
        if ssh $SSH_OPTS ${SSH_USER}@${host} "curl -sf --connect-timeout 2 http://127.0.0.1:9030/consensus >/dev/null 2>&1"; then
            ok "$name healthy (consensus serving after ${elapsed}s)"
            return 0
        fi
        # Fallback: at least check the process is alive
        if ! ssh $SSH_OPTS ${SSH_USER}@${host} "systemctl is-active moor >/dev/null 2>&1"; then
            fail "$name crashed during startup!"
            ssh $SSH_OPTS ${SSH_USER}@${host} "sudo journalctl -u moor --no-pager -n 10 2>/dev/null" || true
            return 1
        fi
        sleep 3
        elapsed=$((elapsed + 3))
    done
    # DA is running but not yet serving consensus — may be waiting for peers
    info "$name running but consensus not yet available (will sync with next DA)"
    return 0
}

for idx in "${DA_INDICES[@]}"; do
    name="${NAMES[$idx]}"
    host="${HOSTS[$idx]}"
    flags="${FLAGS[$idx]}"
    # Strip --da-peers from nodes.conf flags — deploy script provides its own with keys
    svc_flags=$(echo "$flags" | sed 's|~/moor-da|/var/lib/moor|g; s|--da-peers [^ ]*||g')

    # Verify DA keys exist on remote before starting
    KEY_CHECK=$(ssh $SSH_OPTS ${SSH_USER}@${host} "[ -f /var/lib/moor/keys/identity_pk ] && echo OK || echo MISSING")
    if [[ "$KEY_CHECK" == "MISSING" ]]; then
        info "$name: no identity key yet (first deploy — will generate on start)"
    else
        ok "$name: identity key preserved"
    fi

    # Build --da-peers with ALL other DAs' public identity keys (from da-keys.conf)
    DA_PEERS_ARG=""
    for other_idx in "${DA_INDICES[@]}"; do
        [[ "$other_idx" == "$idx" ]] && continue
        other_host="${HOSTS[$other_idx]}"
        other_pk="${DA_KEYS[$other_host]:-}"
        if [[ -z "$other_pk" ]]; then
            fail "No public key for DA $other_host in da-keys.conf!"
            exit 1
        fi
        if [[ -n "$DA_PEERS_ARG" ]]; then
            DA_PEERS_ARG="${DA_PEERS_ARG},${other_host}:9030:${other_pk}"
        else
            DA_PEERS_ARG="${other_host}:9030:${other_pk}"
        fi
    done

    ENV_BLOCK=""
    if [[ $USE_ASAN -eq 1 ]]; then
        ENV_BLOCK='Environment="ASAN_OPTIONS=detect_leaks=0:print_stacktrace=1:abort_on_error=1:log_path=/var/lib/moor/asan"
Environment="UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=0:log_path=/var/lib/moor/ubsan"'
    fi

    cat <<EOF | ssh $SSH_OPTS ${SSH_USER}@${host} "sudo tee /etc/systemd/system/moor.service >/dev/null"
[Unit]
Description=MOOR Directory Authority
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/moor --mode da --advertise ${host} --da-peers ${DA_PEERS_ARG} ${svc_flags}
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
LimitCORE=infinity
WorkingDirectory=/var/lib/moor
${ENV_BLOCK}
StandardError=journal+console

[Install]
WantedBy=multi-user.target
EOF

    ssh $SSH_OPTS ${SSH_USER}@${host} "sudo systemctl daemon-reload && sudo systemctl restart moor" 2>&1
    ok "$name started (peers: $DA_PEERS_ARG)"

    # Wait for this DA to be healthy before starting the next one
    da_wait_healthy "$host" "$name"
done

# Final consensus sync: give DAs a few seconds to exchange votes after all are up
echo -e "${YELLOW}==> Waiting for DA vote exchange (5s)...${NC}"
sleep 5
ok "DA vote exchange window elapsed"

# ==== Phase 7: Start relays ====
echo -e "${YELLOW}==> Starting relays...${NC}"
for idx in "${RELAY_INDICES[@]}"; do
    name="${NAMES[$idx]}"
    host="${HOSTS[$idx]}"
    mode="${MODES[$idx]}"
    flags="${FLAGS[$idx]}"
    svc_flags=$(echo "$flags" | sed 's|~/moor-exit|/var/lib/moor|g; s|~/moor-middle|/var/lib/moor|g')

    ENV_BLOCK=""
    if [[ $USE_ASAN -eq 1 ]]; then
        ENV_BLOCK='Environment="ASAN_OPTIONS=detect_leaks=0:print_stacktrace=1:abort_on_error=1:log_path=/var/lib/moor/asan"
Environment="UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=0:log_path=/var/lib/moor/ubsan"'
    fi

    cat <<EOF | ssh $SSH_OPTS ${SSH_USER}@${host} "sudo tee /etc/systemd/system/moor.service >/dev/null"
[Unit]
Description=MOOR Relay (${name})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/moor --mode ${mode} --advertise ${host} ${svc_flags}
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
LimitCORE=infinity
WorkingDirectory=/var/lib/moor
${ENV_BLOCK}
StandardError=journal+console

[Install]
WantedBy=multi-user.target
EOF

    ssh $SSH_OPTS ${SSH_USER}@${host} "sudo systemctl daemon-reload && sudo systemctl restart moor" 2>&1
    ok "$name started"
done

# ==== Phase 8: Verify all nodes ====
echo -e "${YELLOW}==> Verifying fleet (5s settle)...${NC}"
sleep 5
ALL_OK=1
for ((n=0; n<NODE_COUNT; n++)); do
    status=$(ssh $SSH_OPTS ${SSH_USER}@${HOSTS[$n]} "systemctl is-active moor 2>/dev/null" || echo "dead")
    if [[ "$status" == "active" ]]; then
        ok "${NAMES[$n]} RUNNING"
    else
        fail "${NAMES[$n]} DEAD"
        ssh $SSH_OPTS ${SSH_USER}@${HOSTS[$n]} "sudo journalctl -u moor --no-pager -n 5 2>/dev/null" || true
        ALL_OK=0
    fi
done

rm -f "$TARBALL"

# ==== Phase 9: Deploy to AWS nodes ====
AWS_KEY="$HOME/.ssh/moor_aws.pem"
AWS_SSH="ssh -i $AWS_KEY -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o BatchMode=yes"

if [[ -f "$AWS_KEY" ]]; then
    # Collect all AWS relay IPs from all regions
    AWS_REGIONS=(us-east-1 us-west-2 eu-west-1 eu-central-1 ap-northeast-1 ap-southeast-1 ap-south-1 ap-southeast-2 ca-west-1 af-south-1 eu-south-2)
    declare -a AWS_IPS
    for region in "${AWS_REGIONS[@]}"; do
        while IFS= read -r ip; do
            [[ -n "$ip" && "$ip" != "None" ]] && AWS_IPS+=("$ip")
        done < <(aws ec2 describe-instances --region "$region" \
            --filters "Name=tag:Project,Values=moor-fleet" "Name=instance-state-name,Values=running" \
            --query 'Reservations[*].Instances[*].PublicIpAddress' --output text 2>/dev/null)
    done

    if [[ ${#AWS_IPS[@]} -gt 0 ]]; then
        echo -e "${YELLOW}==> Deploying to ${#AWS_IPS[@]} AWS nodes...${NC}"
        AWS_TARBALL="/tmp/moor-aws-deploy.tar.gz"
        tar czf "$AWS_TARBALL" -C "$SCRIPT_DIR" \
            --exclude='.git' --exclude='obj' --exclude='obj_*' --exclude='*.o' \
            --exclude='./moor' --exclude='./moor_debug' --exclude='./moor_keygen' \
            --exclude='./moor-top' --exclude='promo' --exclude='*.mp3' .

        aws_deploy_node() {
            local ip="$1"
            for attempt in 1 2 3; do
                if scp -i "$AWS_KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -q \
                    "$AWS_TARBALL" ubuntu@${ip}:/tmp/moor-src.tar.gz 2>/dev/null && \
                   $AWS_SSH ubuntu@${ip} \
                    'cd /opt/moor && sudo tar xzf /tmp/moor-src.tar.gz && sudo make clean >/dev/null 2>&1 && sudo make -j$(nproc) 2>&1 | tail -1 && sudo install -m 755 moor /usr/local/bin/moor && sudo mkdir -p /var/lib/moor/keys && sudo chmod 755 /var/lib/moor && sudo chmod 700 /var/lib/moor/keys && sudo systemctl restart moor && sleep 2 && systemctl is-active moor >/dev/null 2>&1' 2>/dev/null; then
                    echo "$ip"
                    return 0
                fi
                [ $attempt -lt 3 ] && sleep 5
            done
            echo "FAIL:$ip"
            return 1
        }

        # Deploy in parallel with per-node tracking
        declare -a AWS_PIDS
        for ip in "${AWS_IPS[@]}"; do
            aws_deploy_node "$ip" &
            AWS_PIDS+=($!)
        done
        wait

        # Verify every AWS node: check binary is fresh AND service is active.
        # The deploy function already verifies inside its SSH session, so
        # this is a second pass to catch any that slipped through.
        echo -e "${YELLOW}==> Verifying AWS nodes (15s settle)...${NC}"
        sleep 15
        DEPLOY_TIME=$(date +%s)
        AWS_OK=0
        AWS_FAIL_LIST=""
        for ip in "${AWS_IPS[@]}"; do
            result=$(ssh -i "$AWS_KEY" -o ConnectTimeout=15 -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
                ubuntu@${ip} "systemctl is-active moor 2>/dev/null && stat -c '%Y' /usr/local/bin/moor 2>/dev/null" 2>/dev/null)
            status=$(echo "$result" | head -1)
            bin_ts=$(echo "$result" | tail -1)
            bin_age=$(( DEPLOY_TIME - ${bin_ts:-0} ))
            if [[ "$status" == "active" && $bin_age -lt 600 ]]; then
                ok "$ip"
                AWS_OK=$((AWS_OK + 1))
            else
                fail "$ip (status=$status, binary ${bin_age}s old)"
                AWS_FAIL_LIST="$AWS_FAIL_LIST $ip"
                ALL_OK=0
            fi
        done

        # Retry failed nodes sequentially (parallel scp often fails on some regions)
        if [[ -n "$AWS_FAIL_LIST" ]]; then
            echo -e "${YELLOW}==> Retrying failed AWS nodes sequentially...${NC}"
            for ip in $AWS_FAIL_LIST; do
                info "retrying $ip..."
                if aws_deploy_node "$ip" | grep -qv FAIL; then
                    ok "$ip (retry succeeded)"
                    AWS_OK=$((AWS_OK + 1))
                else
                    fail "$ip (retry failed)"
                fi
            done
        fi

        rm -f "$AWS_TARBALL"
        ok "AWS: $AWS_OK/${#AWS_IPS[@]} nodes deployed"
        NODE_COUNT=$((NODE_COUNT + AWS_OK))
    fi
fi

# ==== Phase 10: Deploy to Pi ====
PI_HOST="192.168.1.83"
PI_USER="pii"
PI_PASS="io"

if command -v sshpass >/dev/null 2>&1; then
    PI_SSH="sshpass -p $PI_PASS ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new"
    PI_RSYNC="sshpass -p $PI_PASS rsync"

    echo -e "${YELLOW}==> Deploying to Pi ($PI_HOST)...${NC}"

    $PI_RSYNC -az --exclude='.git' --exclude='obj' --exclude='obj_*' \
        --exclude='*.o' --exclude='moor' --exclude='moor_keygen' \
        --exclude='moor-top' --exclude='moor_debug' --exclude='promo' \
        -e "ssh -o StrictHostKeyChecking=accept-new" \
        "${SCRIPT_DIR}/" ${PI_USER}@${PI_HOST}:~/MOOR_PQ_SKIPS/ 2>/dev/null

    $PI_SSH ${PI_USER}@${PI_HOST} bash -s <<'PI_EOF'
        set -e
        cd ~/MOOR_PQ_SKIPS
        make clean 2>/dev/null || true
        make -j$(nproc) 2>&1 | tail -1
        sudo systemctl stop moor 2>/dev/null || true
        sudo cp ./moor /usr/local/bin/moor
        sudo systemctl start moor
PI_EOF

    if [[ $? -eq 0 ]]; then
        ok "Pi deployed and HS restarted"
        NODE_COUNT=$((NODE_COUNT + 1))
    else
        fail "Pi deploy failed"
        ALL_OK=0
    fi
else
    info "sshpass not installed — skipping Pi deploy"
fi

echo ""
if [[ $ALL_OK -eq 1 ]]; then
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN} Fleet deploy complete ($NODE_COUNT nodes)${NC}"
    echo -e "${GREEN}============================================${NC}"
else
    echo -e "${RED}============================================${NC}"
    echo -e "${RED} Deploy finished with errors — check above${NC}"
    echo -e "${RED}============================================${NC}"
fi
