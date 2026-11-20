#!/usr/bin/env bash
# The proxy stage of run.sh: upstreamer in the cluster, serving a pool discovered from Service
# `web`, under a steady client load, through a rollout restart of `web` and through the API
# server going away. Called by run.sh with the cluster name and the repository root.
set -euo pipefail

name=$1
root=$2
here=$(cd "$(dirname "$0")" && pwd)
node=$name-control-plane

archive=${UPSTREAMER_IMAGE_ARCHIVE:-$(nix build "$root#kubernetes-image" --no-link --print-out-paths)}
kind load image-archive "$archive" --name "$name"

kubectl apply -f "$here/proxy.yaml"
kubectl -n shop rollout status deploy/upstreamer --timeout=180s
kubectl -n shop wait --for=condition=Ready pod/loadgen --timeout=180s
sleep 5

sent() { kubectl -n shop logs loadgen 2>/dev/null | wc -l; }
echo "rollout restart of web under load, from request $(sent)"
kubectl -n shop rollout restart deploy/web
kubectl -n shop rollout status deploy/web --timeout=300s
sleep 5

echo "the API server goes away for 60 s, from request $(sent)"
docker exec "$node" mv /etc/kubernetes/manifests/kube-apiserver.yaml /etc/kubernetes/kube-apiserver.yaml.parked
sleep 60
docker exec "$node" mv /etc/kubernetes/kube-apiserver.yaml.parked /etc/kubernetes/manifests/kube-apiserver.yaml
echo "the API server is back"
for _ in $(seq 1 90); do
  kubectl get --raw /readyz >/dev/null 2>&1 && break
  sleep 2
done

# A resync logged after the outage was. The proxy retries with a backoff of up to 30 s, so it
# can come that long after the API server is back.
resynced() {
  kubectl -n shop logs deploy/upstreamer |
    awk '/retrying, last endpoints stay in use/ { out = 1 } out && /: synced, / { found = 1 } END { exit !found }'
}
for _ in $(seq 1 45); do
  resynced && break
  sleep 2
done
sleep 5

codes=$(kubectl -n shop logs loadgen)
total=$(wc -l <<<"$codes")
failed=$(grep -vc '^200$' <<<"$codes" || true)
echo "$total requests, $failed not 200"
grep -vn '^200$' <<<"$codes" | head -20 || true
log=$(kubectl -n shop logs deploy/upstreamer)
echo "$log" | grep -E 'discovery' || true
((failed == 0)) || { echo "$log" | grep -v discovery | tail -40 || true; }

fail=0
((total >= 300)) || { echo "FAIL: the load generator sent only $total requests" >&2; fail=1; }
((failed == 0)) || { echo "FAIL: $failed requests were not answered 200" >&2; fail=1; }
grep -q 'retrying, last endpoints stay in use' <<<"$log" || { echo "FAIL: the outage is not in the proxy's log" >&2; fail=1; }
resynced || { echo "FAIL: the proxy never logged a resync after the outage" >&2; fail=1; }
exit "$fail"
