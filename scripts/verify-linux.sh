#!/usr/bin/env bash
#
# Phase 1 verification on Linux — M3 (real TUN device), M5 (ping across tunnel),
# and M6 (iperf3 throughput + added latency vs. baseline).
#
# Runs BOTH peers on a single host using network namespaces, so no second
# machine is needed. Requires root, iproute2, and iperf3.
#
#   sudo ./scripts/verify-linux.sh
#
# Exit code 0 = all checks passed; non-zero = a check failed.
# It builds the workspace with the `real-tun` feature, generates fresh keys,
# wires two namespaces over a veth "underlay", brings up the tunnel in each,
# then runs connectivity + benchmark checks and tears everything down.

set -euo pipefail

# ---- tunables -------------------------------------------------------------
NS1=vpnt1            # namespace for peer A
NS2=vpnt2            # namespace for peer B
UL1=10.66.0.1       # underlay (carries encrypted UDP) — peer A
UL2=10.66.0.2       # underlay — peer B
TUN1=10.8.0.1       # tunnel IP — peer A
TUN2=10.8.0.2       # tunnel IP — peer B
PORT=51820
DUR=5               # iperf3 seconds
PING_N=30           # pings for latency sample
THROUGHPUT_MIN=0.70 # NFR1: tunnel >= 70% of baseline
LATENCY_MAX_MS=2.0  # NFR2: added latency < 2 ms
# ---------------------------------------------------------------------------

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
BIN="$ROOT/target/release/vpn"
PIDS=()
PASS=0
FAIL=0

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m==>\033[0m %s\n' "$*"; }

check() { # check "name" "condition-cmd..." -> records pass/fail
  local name="$1"; shift
  if "$@"; then green "PASS: $name"; PASS=$((PASS+1));
  else red "FAIL: $name"; FAIL=$((FAIL+1)); fi
}

cleanup() {
  set +e
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  ip netns del "$NS1" 2>/dev/null
  ip netns del "$NS2" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

# ---- preflight ------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || { red "must run as root (sudo)"; exit 2; }
for tool in ip iperf3 ping awk; do
  command -v "$tool" >/dev/null || { red "missing required tool: $tool"; exit 2; }
done

info "Building workspace with real-tun feature (release)"
( cd "$ROOT" && CARGO_NET_OFFLINE=false cargo build --release --features vpn-tunnel/real-tun )
[ -x "$BIN" ] || { red "binary not found at $BIN"; exit 2; }

# ---- keys + configs -------------------------------------------------------
info "Generating keypairs"
A_OUT="$("$BIN" keygen)"; B_OUT="$("$BIN" keygen)"
A_PRIV=$(echo "$A_OUT" | awk -F'"' '/private_key/{print $2}')
A_PUB=$( echo "$A_OUT" | awk -F'"' '/public_key/{print $2}')
B_PRIV=$(echo "$B_OUT" | awk -F'"' '/private_key/{print $2}')
B_PUB=$( echo "$B_OUT" | awk -F'"' '/public_key/{print $2}')

cat > "$WORK/a.toml" <<EOF
private_key = "$A_PRIV"
listen_port = $PORT
interface_address = "$TUN1/24"

[peer]
public_key = "$B_PUB"
endpoint = "$UL2:$PORT"
allowed_ips = ["$TUN2/32"]
EOF

cat > "$WORK/b.toml" <<EOF
private_key = "$B_PRIV"
listen_port = $PORT
interface_address = "$TUN2/24"

[peer]
public_key = "$A_PUB"
endpoint = "$UL1:$PORT"
allowed_ips = ["$TUN1/32"]
EOF

# ---- namespaces + underlay veth ------------------------------------------
info "Creating namespaces and underlay link"
ip netns add "$NS1"; ip netns add "$NS2"
ip link add veth-a type veth peer name veth-b
ip link set veth-a netns "$NS1"; ip link set veth-b netns "$NS2"
ip -n "$NS1" addr add "$UL1/24" dev veth-a
ip -n "$NS2" addr add "$UL2/24" dev veth-b
ip -n "$NS1" link set veth-a up; ip -n "$NS1" link set lo up
ip -n "$NS2" link set veth-b up; ip -n "$NS2" link set lo up

check "underlay connectivity (veth)" \
  ip netns exec "$NS1" ping -c 2 -W 2 "$UL2" >/dev/null

# ---- bring up tunnels (M3) -----------------------------------------------
info "Bringing up tunnel in each namespace (M3: real TUN device)"
ip netns exec "$NS1" "$BIN" up --config "$WORK/a.toml" --iface vpn0 \
  >"$WORK/a.log" 2>&1 & PIDS+=($!)
ip netns exec "$NS2" "$BIN" up --config "$WORK/b.toml" --iface vpn0 \
  >"$WORK/b.log" 2>&1 & PIDS+=($!)
sleep 3  # allow handshake (NFR4 target < 1s; we give margin)

check "TUN interface vpn0 exists in ns A" \
  ip netns exec "$NS1" ip link show vpn0 >/dev/null
check "TUN interface vpn0 exists in ns B" \
  ip netns exec "$NS2" ip link show vpn0 >/dev/null

# ---- ping across the tunnel (M5) -----------------------------------------
info "Pinging across the encrypted tunnel (M5)"
check "ping $TUN2 from A over tunnel" \
  ip netns exec "$NS1" ping -c 5 -W 2 "$TUN2" >/dev/null
check "ping $TUN1 from B over tunnel" \
  ip netns exec "$NS2" ping -c 5 -W 2 "$TUN1" >/dev/null

# ---- M6: throughput vs baseline ------------------------------------------
iperf_mbps() { # iperf_mbps <server-ns> <bind-ip> <client-ns> <target-ip>
  ip netns exec "$1" iperf3 -s -1 -B "$2" -D
  sleep 1
  ip netns exec "$3" iperf3 -c "$4" -t "$DUR" -f m 2>/dev/null \
    | awk '/receiver/{print $(NF-2)}' | tail -1
}

info "Measuring baseline throughput (underlay) and tunnel throughput (M6/NFR1)"
BASE=$(iperf_mbps "$NS2" "$UL2" "$NS1" "$UL2"); sleep 1
TUNT=$(iperf_mbps "$NS2" "$TUN2" "$NS1" "$TUN2")
info "baseline=${BASE:-?} Mbps  tunnel=${TUNT:-?} Mbps"

throughput_ok() {
  [ -n "${BASE:-}" ] && [ -n "${TUNT:-}" ] || return 1
  awk -v b="$BASE" -v t="$TUNT" -v m="$THROUGHPUT_MIN" \
    'BEGIN{ exit !(b>0 && (t/b)>=m) }'
}
check "tunnel throughput >= ${THROUGHPUT_MIN} x baseline (NFR1)" throughput_ok

# ---- M6: added latency ----------------------------------------------------
ping_avg_ms() { # ping_avg_ms <ns> <ip>
  ip netns exec "$1" ping -c "$PING_N" -i 0.2 -W 2 "$2" 2>/dev/null \
    | awk -F'/' '/rtt|round-trip/{print $5}'
}
info "Measuring added latency (M6/NFR2)"
LAT_BASE=$(ping_avg_ms "$NS1" "$UL2")
LAT_TUN=$(ping_avg_ms "$NS1" "$TUN2")
info "latency baseline=${LAT_BASE:-?} ms  tunnel=${LAT_TUN:-?} ms"

latency_ok() {
  [ -n "${LAT_BASE:-}" ] && [ -n "${LAT_TUN:-}" ] || return 1
  awk -v b="$LAT_BASE" -v t="$LAT_TUN" -v m="$LATENCY_MAX_MS" \
    'BEGIN{ exit !((t-b) < m) }'
}
check "added latency < ${LATENCY_MAX_MS} ms (NFR2)" latency_ok

# ---- teardown check (FR1) -------------------------------------------------
info "Verifying clean teardown on SIGTERM (FR1)"
for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
sleep 1
PIDS=()
check "tunnel processes exited on signal" bash -c '! pgrep -f "vpn up --config" >/dev/null'

# ---- summary --------------------------------------------------------------
echo
info "RESULTS: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || { red "Phase 1 Linux verification FAILED"; exit 1; }
green "Phase 1 Linux verification PASSED (M3 + M5 + M6)"
