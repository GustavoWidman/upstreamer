#!/usr/bin/env bash
set -euo pipefail

KIND="nix run nixpkgs#kind --"
KUBECTL="nix run nixpkgs#kubectl --"
CLUSTER="upstreamer-e2e"

info()  { echo -e "\033[1m[TEST]\033[0m $*"; }
pass()  { echo -e "\033[32m[PASS]\033[0m $*"; }
fail()  { echo -e "\033[31m[FAIL]\033[0m $*"; EXIT=1; }

EXIT=0

cleanup() {
    info "cleaning up kind cluster '$CLUSTER'"
    $KIND delete cluster --name "$CLUSTER" 2>/dev/null || true
}
trap cleanup EXIT

# --- setup ---
info "creating kind cluster"
$KIND create cluster --config e2e/kind.yaml --wait 120s

info "building upstreamer image"
docker build -t upstreamer:latest -f e2e/Dockerfile .

info "loading image into kind"
$KIND load docker-image upstreamer:latest --name "$CLUSTER"

info "deploying backend"
$KUBECTL apply -f e2e/manifests/backend.yaml
$KUBECTL rollout status deployment/backend --timeout=60s

info "deploying upstreamer"
$KUBECTL apply -f e2e/manifests/upstreamer.yaml
$KUBECTL rollout status deployment/upstreamer --timeout=60s

info "port-forwarding upstreamer"
$KUBECTL port-forward svc/upstreamer 18080:8080 &
PF_PROXY_PID=$!
$KUBECTL port-forward svc/upstreamer 19090:9090 &
PF_METRICS_PID=$!
sleep 2

check() {
    local url="$1" expect="$2" label="$3"
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null) || code="000"
    if [ "$code" = "$expect" ]; then
        pass "$label (got $code)"
    else
        fail "$label (expected $expect, got $code)"
    fi
}

# --- test: routing ---
info "=== test: routing ==="
BODY=$(curl -s --max-time 5 http://127.0.0.1:18080/ 2>/dev/null) || BODY=""
if echo "$BODY" | grep -q "backend ok"; then
    pass "proxies to backend (body contains 'backend ok')"
else
    fail "proxy routing (body: '${BODY:0:100}')"
fi

# --- test: health endpoint ---
info "=== test: health endpoint ==="
check http://127.0.0.1:19090/healthz 200 "healthz returns 200"

# --- test: rate limiting ===
info "=== test: rate limiting ==="
info "sending 200 rapid requests (burst=150, rate=100)"
RATE_429=0
for i in $(seq 1 200); do
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 http://127.0.0.1:18080/ 2>/dev/null) || code="000"
    [ "$code" = "429" ] && RATE_429=$((RATE_429 + 1))
done
if [ "$RATE_429" -gt 0 ]; then
    pass "rate limiting triggered ($RATE_429 requests got 429)"
else
    fail "rate limiting (expected some 429s, got 0)"
fi

# --- test: metrics ---
info "=== test: metrics ==="
METRICS=$(curl -s --max-time 5 http://127.0.0.1:19090/metrics 2>/dev/null) || METRICS=""
if echo "$METRICS" | grep -q "upstreamer_total_origins"; then
    pass "metrics endpoint serves prometheus data"
else
    fail "metrics endpoint (no upstreamer metrics found)"
fi

# --- test: config hot-reload ---
info "=== test: config hot-reload ==="
info "patching configmap to change rate limit"
$KUBECTL patch configmap upstreamer-config --type merge -p \
  '{"data":{"upstreamer.toml":"listen = \"0.0.0.0:8080\"\nmetrics_addr = \"0.0.0.0:9090\"\n\n[ratelimit]\nrate = 10\nburst = 15\n\n[health]\n[health.active]\nenabled = true\ninterval = \"5s\"\ntimeout = \"3s\"\nhealthy_threshold = 2\nunhealthy_threshold = 3\n\n[health.passive]\nenabled = true\nfailure_threshold = 5\nsuccess_threshold = 2\nobservation_window = \"60s\"\n\n[[routes]]\nmatch_path = \"/\"\nlb_algorithm = \"round_robin\"\n\n[[routes.pools]]\nname = \"backend\"\n\n[[routes.pools.origins]]\nurl = \"http://backend:80\"\n\n[kubernetes]\nnamespace = \"default\"\nlabel_selector = \"app=backend\"\n"}}'

info "waiting for config sync and reload (10s)"
sleep 10

info "sending 30 rapid requests (burst=15, rate=10)"
HOT_429=0
for i in $(seq 1 30); do
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 http://127.0.0.1:18080/ 2>/dev/null) || code="000"
    [ "$code" = "429" ] && HOT_429=$((HOT_429 + 1))
done
if [ "$HOT_429" -gt 10 ]; then
    pass "hot-reload applied stricter rate limit ($HOT_429 got 429 vs $RATE_429 before)"
else
    fail "hot-reload rate limit change (only $HOT_429 got 429, expected > 10)"
fi

# --- cleanup ---
kill $PF_PROXY_PID $PF_METRICS_PID 2>/dev/null || true

info ""
info "=== results ==="
if [ "$EXIT" = "0" ]; then
    pass "all tests passed"
else
    fail "some tests failed"
fi

exit $EXIT
