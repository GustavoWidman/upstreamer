#!/bin/bash
# bench/compare.sh — benchmark upstreamer against nginx, haproxy, caddy, apache
#
# Usage: bench/compare.sh [CONNS] [REQUESTS]
#   Defaults: 50 connections, 100000 requests
#
# Requires: nix (for oha, nginx, haproxy, caddy, apacheHttpd), cargo
set -euo pipefail

cd "$(dirname "$0")/.."

CONNS="${1:-50}"
REQUESTS="${2:-100000}"
OHA="nix run nixpkgs#oha --"
WARMUP=5000

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
RESET='\033[0m'

cleanup() {
    local pids
    pids=$(jobs -p 2>/dev/null)
    [ -n "$pids" ] && kill $pids 2>/dev/null || true
    wait 2>/dev/null || true
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

bench() {
    local label=$1 port=$2
    echo -e "${BOLD}Benchmarking ${label}...${RESET}"
    $OHA "http://127.0.0.1:${port}" -c "$CONNS" -n "$REQUESTS" --no-tui 2>&1
}

parse_result() {
    awk -v label="$1" '
        /^  Requests\/sec:/ { rps = $2 }
        /^  Slowest:/ { slow = $2 }
        /^  Fastest:/ { fast = $2 }
        /50.00%/ { p50 = $3 }
        /99.00%/ { p99 = $3 }
        /99.90%/ { p999 = $3 }
        /99.99%/ { p9999 = $3 }
        END {
            printf "%-22s %10s %8s %8s %8s %8s %8s %8s\n", \
                label, rps, fast, p50, p99, p999, p9999, slow
        }
    '
}

warmup() {
    local port=$1
    $OHA "http://127.0.0.1:${port}" -c "$CONNS" -n "$WARMUP" --no-tui > /dev/null 2>&1 || true
    sleep 0.3
}

# --- Setup ---
kill_ports $ALL_PORTS

echo -e "${BOLD}Building upstreamer...${RESET}"
cargo build --release --manifest-path Cargo.toml 2>&1 | tail -1

echo -e "${BOLD}Starting backend server...${RESET}"
cargo run --example bench-backend --release 2>/dev/null &
wait_for $BACKEND_PORT "bench-backend"

echo -e "${BOLD}Warming backend...${RESET}"
warmup $BACKEND_PORT

# --- Backend direct ---
BACKEND_RAW=$(bench "backend (direct)" $BACKEND_PORT)

# --- Upstreamer ---
echo -e "${BOLD}Starting upstreamer...${RESET}"
./target/release/upstreamer --config bench/upstreamer.toml --log-level warn 2>/dev/null &
wait_for $UPSTREAMER_PORT "upstreamer"
warmup $UPSTREAMER_PORT
UPSTREAMER_RAW=$(bench "upstreamer" $UPSTREAMER_PORT)

# --- nginx 1 worker ---
echo -e "${BOLD}Starting nginx (1 worker)...${RESET}"
nix run nixpkgs#nginx -- -c "$(pwd)/bench/nginx-1w.conf" -p "$(pwd)/bench/" 2>/dev/null &
wait_for $NGINX1W_PORT "nginx-1w"
warmup $NGINX1W_PORT
NGINX1_RAW=$(bench "nginx (1w)" $NGINX1W_PORT)

kill_ports $NGINX1W_PORT

# --- nginx auto ---
echo -e "${BOLD}Starting nginx (auto)...${RESET}"
nix run nixpkgs#nginx -- -c "$(pwd)/bench/nginx-auto.conf" -p "$(pwd)/bench/" 2>/dev/null &
wait_for $NGINX_AUTO_PORT "nginx-auto"
warmup $NGINX_AUTO_PORT
NGINXA_RAW=$(bench "nginx (auto)" $NGINX_AUTO_PORT)

kill_ports $NGINX_AUTO_PORT

# --- Caddy ---
echo -e "${BOLD}Starting caddy...${RESET}"
nix run nixpkgs#caddy -- run --config "$(pwd)/bench/Caddyfile" 2>/dev/null &
wait_for $CADDY_PORT "caddy"
warmup $CADDY_PORT
CADDY_RAW=$(bench "caddy" $CADDY_PORT)

kill_ports $CADDY_PORT

# --- HAProxy ---
echo -e "${BOLD}Starting haproxy...${RESET}"
nix run nixpkgs#haproxy -- -f "$(pwd)/bench/haproxy.cfg" 2>/dev/null &
wait_for $HAPROXY_PORT "haproxy"
warmup $HAPROXY_PORT
HAPROXY_RAW=$(bench "haproxy" $HAPROXY_PORT)

kill_ports $HAPROXY_PORT

# --- Apache ---
echo -e "${BOLD}Starting apache...${RESET}"
APACHE_ROOT=$(nix eval --raw nixpkgs#apacheHttpd 2>/dev/null)
nix shell nixpkgs#apacheHttpd -c httpd -d "$APACHE_ROOT" -f "$(pwd)/bench/apache-httpd.conf" -D FOREGROUND 2>/dev/null &
APACHE_OK=true
wait_for $APACHE_PORT "apache" || APACHE_OK=false
if $APACHE_OK; then
    warmup $APACHE_PORT
    APACHE_RAW=$(bench "apache" $APACHE_PORT)
else
    APACHE_RAW=""
    echo -e "${DIM}Skipping apache (failed to start)${RESET}"
fi

kill_ports $APACHE_PORT

# --- Results ---
echo ""
echo -e "${BOLD}=====================================================================${RESET}"
echo -e "${BOLD}  BENCHMARK RESULTS  (conns=${CONNS}, requests=${REQUESTS}, cores=$(cpu_count))${RESET}"
echo -e "${BOLD}=====================================================================${RESET}"
echo -e "${DIM}(all times in ms)${RESET}"
echo ""
printf "%-22s %10s %8s %8s %8s %8s %8s %8s\n" \
    "Target" "RPS" "Fastest" "p50" "p99" "p99.9" "p99.99" "Slowest"
echo "-----------------------------------------------------------------------------"

echo "$BACKEND_RAW"   | parse_result "backend (direct)"
echo "$UPSTREAMER_RAW" | parse_result "upstreamer"
echo "$NGINX1_RAW"    | parse_result "nginx (1 worker)"
echo "$NGINXA_RAW"    | parse_result "nginx (auto)"
echo "$CADDY_RAW"     | parse_result "caddy"
echo "$HAPROXY_RAW"   | parse_result "haproxy"
if [ -n "$APACHE_RAW" ]; then
    echo "$APACHE_RAW" | parse_result "apache"
fi
echo ""
