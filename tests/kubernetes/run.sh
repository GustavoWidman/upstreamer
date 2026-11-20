#!/usr/bin/env bash
# Runs upstreamer's Kubernetes discovery against a throwaway kind cluster, with the credentials
# of the ServiceAccount that docs/kubernetes-rbac.yaml allows, and nothing else.
#
#   tests/kubernetes/run.sh client   the client's tests against the real API server (default)
#   tests/kubernetes/run.sh proxy    the proxy serving a Kubernetes-discovered pool: a rollout
#                                    restart under load, and the API server going away
#
# Needs docker, kind, kubectl, and a Rust toolchain on PATH; from the repository root:
#
#   nix shell nixpkgs#kind nixpkgs#kubectl --command nix develop --command tests/kubernetes/run.sh
#
# The cluster is named upstreamer-e2e and is deleted on exit.
set -euo pipefail

stage=${1:-client}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
name=${KIND_CLUSTER_NAME:-upstreamer-e2e}
work=$(mktemp -d)
export UPSTREAMER_KIND_ADMIN=$work/admin.kubeconfig
export UPSTREAMER_KIND_RESTRICTED=$work/restricted.kubeconfig
export UPSTREAMER_KIND_NODE=$name-control-plane

cleanup() {
  kind delete cluster --name "$name" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

kind delete cluster --name "$name" >/dev/null 2>&1 || true
kind create cluster --name "$name" --config "$here/kind.yaml" --kubeconfig "$UPSTREAMER_KIND_ADMIN" --wait 180s
export KUBECONFIG=$UPSTREAMER_KIND_ADMIN

kubectl apply -f "$here/workload.yaml"
kubectl apply -f "$root/docs/kubernetes-rbac.yaml"
kubectl -n shop rollout status deploy/web --timeout=300s

# A kubeconfig for the ServiceAccount: its token and the cluster's CA and address.
server=$(kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.server}')
ca=$(kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
token=$(kubectl -n shop create token upstreamer --duration=2h)
cat >"$UPSTREAMER_KIND_RESTRICTED" <<YAML
apiVersion: v1
kind: Config
current-context: upstreamer
clusters:
  - name: kind
    cluster:
      server: $server
      certificate-authority-data: $ca
users:
  - name: upstreamer
    user:
      token: $token
contexts:
  - name: upstreamer
    context: {cluster: kind, user: upstreamer}
YAML

case $stage in
  client)
    cd "$root"
    cargo test --locked --features kubernetes --lib kind_ -- --ignored --test-threads 1 --nocapture
    ;;
  proxy)
    "$here/proxy.sh" "$name" "$root"
    ;;
  *)
    echo "usage: $0 [client|proxy]" >&2
    exit 2
    ;;
esac
