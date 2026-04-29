#!/bin/bash
# bench/compare.sh — benchmark upstreamer against nginx, haproxy, caddy, apache
#
# Usage: bench/compare.sh [REQUESTS]
#   Default REQUESTS: 100000
#
# Per proxy this script:
#   1. probes a concurrency ladder to find the highest level still serving
#      100% 2xx responses (informational; shown as "Cap" in the result);
#   2. benches the proxy at fixed BENCH_CONNS concurrency with HTTP keepalive
#      on, so latency reflects per-request work at moderate steady load;
#   3. flags the run invalid if any non-2xx or oha-level errors slip through.
#
# Env:
#   COOLDOWN     seconds to idle between bench rounds (default: 10)
#   BENCH_CONNS  oha concurrency for the latency bench (default: 50). Higher
#                values trigger proxy-side buffering tricks (apache event MPM)
#                that make latency numbers meaningless.
#
# Requires: nix (for oha, nginx, haproxy, caddy, apacheHttpd), cargo
set -euo pipefail

cd "$(dirname "$0")/.."

# Backwards-compat: old form was `compare.sh CONNS REQUESTS` (CONNS is now
# auto-tuned and ignored). New form is `compare.sh REQUESTS`.
if [ $# -ge 2 ]; then
    REQUESTS="$2"
else
    REQUESTS="${1:-100000}"
fi
COOLDOWN="${COOLDOWN:-10}"
BENCH_CONNS="${BENCH_CONNS:-50}"
OHA="nix run nixpkgs#oha --"
WARMUP=2000
PROBE_REQ=2000
PROBE_MAX=100000

BACKEND_PORT=18080
UPSTREAMER_PORT=19080
NGINX1W_PORT=19081
NGINX_AUTO_PORT=19082
CADDY_PORT=19083
HAPROXY_PORT=19084
APACHE_PORT=19085

ALL_PORTS="$BACKEND_PORT $UPSTREAMER_PORT $NGINX1W_PORT $NGINX_AUTO_PORT $CADDY_PORT $HAPROXY_PORT $APACHE_PORT"

BOLD='\033[1m'
DIM='\033[2m'
RED='\033[31m'
YELLOW='\033[33m'
RESET='\033[0m'

cleanup() {
    local pids
    pids=$(jobs -p 2>/dev/null)
    [ -n "$pids" ] && kill $pids 2>/dev/null || true
    wait 2>/dev/null || true
    kill_ports $ALL_PORTS
    rm -f bench/*.pid
}
trap cleanup EXIT

kill_ports() {
    for port in "$@"; do
        if [ "$(uname)" = "Linux" ] && command -v fuser >/dev/null 2>&1; then
            fuser -k "${port}/tcp" 2>/dev/null || true
        else
            local pids
            pids=$(lsof -ti tcp:"$port" 2>/dev/null || true)
            [ -n "$pids" ] && kill $pids 2>/dev/null || true
        fi
    done
    sleep 0.3
}

cpu_count() {
    if command -v nproc >/dev/null 2>&1; then
        nproc
    else
        sysctl -n hw.ncpu 2>/dev/null || echo "?"
    fi
}

wait_for() {
    local port=$1 name=$2
    for i in $(seq 1 30); do
        if curl -sf "http://127.0.0.1:${port}/" > /dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
    done
    echo "ERROR: ${name} on port ${port} did not become ready" >&2
    return 1
}

warmup() {
    local port=$1 conns=$2
    $OHA "http://127.0.0.1:${port}" -c "$conns" -n "$WARMUP" --no-tui > /dev/null 2>&1 || true
    sleep 0.3
}

cooldown() {
    sleep "$COOLDOWN"
}

# Extract the status code distribution lines from raw oha output.
status_codes() {
    awk '/^Status code distribution:/{p=1;next} p && /\[/{print} p && !/\[/ && /[^[:space:]]/{p=0}'
}

# Extract any "Error distribution:" lines from oha output (connection errors,
# timeouts, etc. — these don't show up as HTTP status codes).
error_lines() {
    awk '/^Error distribution:/{p=1;next} p && /\[/{print} p && !/\[/ && /[^[:space:]]/{p=0}'
}

# Returns 0 if the run is acceptable (all 2xx, oha-error rate below threshold).
# Hard-fails on any non-2xx. Soft-warns on oha errors below ERR_TOLERANCE_BPS
# (basis points of REQUESTS, default 10 = 0.1%); fails above it.
ERR_TOLERANCE_BPS="${ERR_TOLERANCE_BPS:-10}"

# Total oha-error count from the raw output (sum of [N] in Error distribution).
err_count() {
    echo "$1" | error_lines | grep -oE '\[[0-9]+\]' | tr -d '[]' \
        | awk '{s+=$1} END {print s+0}'
}

check_status() {
    local label=$1 raw=$2
    local bad errs err_total threshold
    bad=$(echo "$raw" | status_codes | grep -vE '\[2[0-9]{2}\]' || true)
    errs=$(echo "$raw" | error_lines || true)
    if [ -n "$bad" ]; then
        echo -e "${RED}WARNING: ${label} returned non-2xx responses — results invalid:${RESET}" >&2
        echo "$bad" >&2
        return 1
    fi
    if [ -n "$errs" ]; then
        err_total=$(err_count "$raw")
        threshold=$(( REQUESTS * ERR_TOLERANCE_BPS / 10000 ))
        if [ "$err_total" -gt "$threshold" ]; then
            echo -e "${RED}WARNING: ${label} oha errors ${err_total}/${REQUESTS} exceed tolerance (${ERR_TOLERANCE_BPS} bps) — results invalid:${RESET}" >&2
            echo "$errs" >&2
            return 1
        fi
        echo -e "${YELLOW}NOTE: ${label} had ${err_total}/${REQUESTS} oha errors (within tolerance):${RESET}" >&2
        echo "$errs" >&2
    fi
    return 0
}

# Probe a single concurrency level. Returns 0 if 100% 2xx and oha errors are
# within ERR_TOLERANCE_BPS of the probe size; 1 otherwise.
probe_one() {
    local label=$1 port=$2 c=$3
    local probe_n raw bad err_total threshold
    probe_n=$(( PROBE_REQ > c ? PROBE_REQ : c ))
    echo -e "${DIM}  probing ${label} @ conns=${c} (n=${probe_n})...${RESET}" >&2
    raw=$($OHA "http://127.0.0.1:${port}" -c "$c" -n "$probe_n" --no-tui 2>&1 || true)
    bad=$(echo "$raw" | status_codes | grep -vE '\[2[0-9]{2}\]' || true)
    [ -n "$bad" ] && return 1
    err_total=$(err_count "$raw")
    threshold=$(( probe_n * ERR_TOLERANCE_BPS / 10000 ))
    [ "$err_total" -gt "$threshold" ] && return 1
    return 0
}

# Find the highest concurrency that stays within tolerance via doubling search
# followed by a binary refinement between the last good level and the first
# bad one. Refinement stops when the gap is within max(lo/10, 25).
find_capacity() {
    local label=$1 port=$2
    local last_ok=0 first_fail=0 c lo hi mid gap stop
    c=50
    while [ "$c" -le "$PROBE_MAX" ]; do
        if probe_one "$label" "$port" "$c"; then
            last_ok=$c
            sleep 0.5
            c=$(( c * 2 ))
        else
            first_fail=$c
            break
        fi
    done
    if [ "$first_fail" -gt 0 ] && [ "$last_ok" -gt 0 ]; then
        lo=$last_ok
        hi=$first_fail
        while :; do
            gap=$(( hi - lo ))
            stop=$(( lo / 10 > 25 ? lo / 10 : 25 ))
            [ "$gap" -le "$stop" ] && break
            mid=$(( (lo + hi) / 2 ))
            sleep 0.5
            if probe_one "$label" "$port" "$mid"; then
                lo=$mid
            else
                hi=$mid
            fi
        done
        last_ok=$lo
    fi
    [ "$last_ok" = 0 ] && last_ok=50
    printf '%d' "$last_ok"
}

start_backend() {
    cargo run --example bench-backend --release 2>/dev/null &
    wait_for $BACKEND_PORT "bench-backend"
    warmup $BACKEND_PORT 50
}

stop_backend() {
    kill_ports $BACKEND_PORT
}

# Run the latency bench at fixed moderate concurrency with HTTP keepalive on.
latency_bench() {
    local label=$1 port=$2 conns=$3
    echo -e "${BOLD}Benchmarking ${label} (conns=${conns}, n=${REQUESTS})...${RESET}" >&2
    $OHA "http://127.0.0.1:${port}" -c "$conns" -n "$REQUESTS" --no-tui 2>&1
}

# bench_proxy <label> <port> <start-cmd...>
# Reboots backend, starts proxy, probes capacity, runs honest-latency bench,
# tears everything down. Emits "CONNS=<n>\n<raw oha output>" on stdout.
bench_proxy() {
    local label=$1 port=$2
    shift 2
    {
        echo -e "${BOLD}Starting ${label}...${RESET}"
        start_backend
    } >&2
    "$@" >/dev/null 2>&1 &
    if ! wait_for "$port" "$label" >&2; then
        stop_backend >&2
        cooldown
        return 1
    fi
    warmup "$port" "$BENCH_CONNS" >&2
    local cap raw
    cap=$(find_capacity "$label" "$port")
    raw=$(latency_bench "$label" "$port" "$BENCH_CONNS")
    kill_ports "$port" >&2
    stop_backend >&2
    cooldown
    if ! check_status "$label" "$raw"; then
        echo "$raw" | tail -30 >&2
        return 1
    fi
    printf 'CAP=%d\n%s' "$cap" "$raw"
}

run_upstreamer() {
    ./target/release/upstreamer --config bench/upstreamer.toml --log-level warn 2>/dev/null
}
run_nginx_1w() {
    nix run nixpkgs#nginx -- -c "$(pwd)/bench/nginx-1w.conf" -p "$(pwd)/bench/" 2>/dev/null
}
run_nginx_auto() {
    nix run nixpkgs#nginx -- -c "$(pwd)/bench/nginx-auto.conf" -p "$(pwd)/bench/" 2>/dev/null
}
run_caddy() {
    nix run nixpkgs#caddy -- run --config "$(pwd)/bench/Caddyfile" 2>/dev/null
}
run_haproxy() {
    nix run nixpkgs#haproxy -- -f "$(pwd)/bench/haproxy.cfg" 2>/dev/null
}
run_apache() {
    local apache_root
    apache_root=$(nix eval --raw nixpkgs#apacheHttpd 2>/dev/null)
    nix shell nixpkgs#apacheHttpd -c httpd -d "$apache_root" -f "$(pwd)/bench/apache-httpd.conf" -D FOREGROUND 2>/dev/null
}

parse_result() {
    awk -v label="$1" '
        /^CAP=/ { sub(/^CAP=/, ""); cap = $0 }
        /^  Requests\/sec:/ { rps = $2 }
        /^  Slowest:/ { slow = $2 }
        /50.00%/ { p50 = $3 }
        /99.00%/ { p99 = $3 }
        /99.90%/ { p999 = $3 }
        /99.99%/ { p9999 = $3 }
        END {
            if (rps == "") {
                printf "%-22s %10s\n", label, "(skipped)"
            } else {
                if (cap == "") cap = "-"
                printf "%-22s %6s %10s %8s %8s %8s %8s %8s\n", \
                    label, cap, rps, p50, p99, p999, p9999, slow
            }
        }
    '
}

# --- Setup ---
kill_ports $ALL_PORTS

# Raise file descriptor limit so the no-keepalive runs don't trip on it.
ulimit -n 65536 2>/dev/null || true

echo -e "${BOLD}Building upstreamer...${RESET}"
cargo build --release --manifest-path Cargo.toml 2>&1 | tail -1

# --- Backend direct ---
echo -e "${BOLD}Starting backend (direct bench)...${RESET}"
start_backend
BACKEND_CAP=$(find_capacity "backend" $BACKEND_PORT)
BACKEND_RAW=$(latency_bench "backend (direct)" $BACKEND_PORT "$BENCH_CONNS")
stop_backend
cooldown
if check_status "backend (direct)" "$BACKEND_RAW"; then
    BACKEND_RAW=$(printf 'CAP=%d\n%s' "$BACKEND_CAP" "$BACKEND_RAW")
else
    BACKEND_RAW=""
fi

# --- Proxies ---
UPSTREAMER_RAW=$(bench_proxy "upstreamer"   $UPSTREAMER_PORT  run_upstreamer  || echo "")
NGINX1_RAW=$(   bench_proxy "nginx (1w)"    $NGINX1W_PORT     run_nginx_1w    || echo "")
NGINXA_RAW=$(   bench_proxy "nginx (auto)"  $NGINX_AUTO_PORT  run_nginx_auto  || echo "")
CADDY_RAW=$(    bench_proxy "caddy"         $CADDY_PORT       run_caddy       || echo "")
HAPROXY_RAW=$(  bench_proxy "haproxy"       $HAPROXY_PORT     run_haproxy     || echo "")
APACHE_RAW=$(   bench_proxy "apache"        $APACHE_PORT      run_apache      || echo "")

# --- Results ---
echo ""
echo -e "${BOLD}=====================================================================${RESET}"
echo -e "${BOLD}  BENCHMARK RESULTS  (bench-conns=${BENCH_CONNS}, requests=${REQUESTS}, cores=$(cpu_count))${RESET}"
echo -e "${DIM}  Cap = max probed concurrency that stayed 100% 2xx (informational)${RESET}"
echo -e "${BOLD}=====================================================================${RESET}"
echo -e "${DIM}(all times in ms)${RESET}"
echo ""
printf "%-22s %6s %10s %8s %8s %8s %8s %8s\n" \
    "Target" "Cap" "RPS" "p50" "p99" "p99.9" "p99.99" "Slowest"
echo "-----------------------------------------------------------------------------------"

echo "$BACKEND_RAW"    | parse_result "backend (direct)"
echo "$UPSTREAMER_RAW" | parse_result "upstreamer"
echo "$NGINX1_RAW"     | parse_result "nginx (1 worker)"
echo "$NGINXA_RAW"     | parse_result "nginx (auto)"
echo "$CADDY_RAW"      | parse_result "caddy"
echo "$HAPROXY_RAW"    | parse_result "haproxy"
echo "$APACHE_RAW"     | parse_result "apache"
echo ""
