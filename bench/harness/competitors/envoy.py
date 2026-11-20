from ..scenarios import (
    CLIENT_HEADER,
    HEALTH_INTERVAL_S,
    HEALTH_PATH,
    LIMIT_CLIENT_RATE,
    LIMIT_CONST_RATE,
    Feature,
)
from ..scenarios import Capability as C
from ..servers import ALL, NO_FILES, Context, Server, exe

F = Feature
LOCAL_RATELIMIT = "type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit"
ALWAYS = "{ default_value: { numerator: 100, denominator: HUNDRED }, runtime_key: %s }"


def _bucket(rate: int) -> str:
    return f"{{ max_tokens: {rate}, tokens_per_fill: {rate}, fill_interval: 1s }}"


def features(ctx: Context) -> dict[str, str]:
    f = ctx.features
    v = ctx.values()
    top, hcm, route, filters, cluster, endpoints = [], [], [], [], [], []
    if F.LB_LEAST in f:
        cluster.append("      lb_policy: LEAST_REQUEST")
    if F.LB_HASH in f:
        cluster.append("      lb_policy: MAGLEV")
        route.append(f"hash_policy: [{{ header: {{ header_name: {CLIENT_HEADER} }} }}]")
    if f & {F.LB_ROUND_ROBIN, F.LB_LEAST, F.LB_HASH}:
        endpoints.append(
            "              - endpoint:\n                  address:\n                    socket_address: "
            f'{{ address: "{v["origin_host"]}", port_value: {v["origin_port2"]} }}'
        )
    if F.HEALTH in f:
        cluster.append(
            "      health_checks: [{ timeout: 2s, interval: %ss, unhealthy_threshold: 3, healthy_threshold: 2, "
            'http_health_check: { path: "%s" } }]' % (HEALTH_INTERVAL_S, HEALTH_PATH)
        )
    if F.TRUSTED in f:
        hcm.append("                xff_num_trusted_hops: 1")
    limit = None
    if F.LIMIT_CLIENT in f:
        if F.TRUSTED in f:
            action, key = "remote_address: {}", "remote_address"
        else:
            action, key = f"request_headers: {{ header_name: {CLIENT_HEADER}, descriptor_key: client }}", "client"
        route.append(f"rate_limits: [{{ actions: [{{ {action} }}] }}]")
        limit = (
            f"token_bucket: {_bucket(LIMIT_CLIENT_RATE)}, always_consume_default_token_bucket: false, "
            f"max_dynamic_descriptors: 65536, descriptors: [{{ entries: [{{ key: {key} }}], "
            f"token_bucket: {_bucket(LIMIT_CLIENT_RATE)} }}]"
        )
    if F.LIMIT_CONST in f:
        limit = f"token_bucket: {_bucket(LIMIT_CONST_RATE)}"
    if limit:
        filters.append(
            "                  - { name: envoy.filters.http.local_ratelimit, typed_config: { "
            f'"@type": {LOCAL_RATELIMIT}, stat_prefix: rate, '
            f"filter_enabled: {ALWAYS % 'rate_enabled'}, filter_enforced: {ALWAYS % 'rate_enforced'}, {limit} }} }}"
        )
    if F.METRICS in f:
        top.append(f'admin:\n  address:\n    socket_address: {{ address: "{v["host"]}", port_value: {v["admin_port"]} }}\n')
    return {
        "top_extra": "\n".join(top),
        "hcm_extra": "\n".join(hcm),
        "route_extra": "".join(", " + r for r in route),
        "filters_extra": "\n".join(filters),
        "cluster_extra": "\n".join(cluster),
        "endpoints_extra": "\n".join(endpoints),
    }


SERVER = Server(
    name="envoy",
    tool="envoy",
    capabilities=ALL - {C.STATIC},
    not_applicable={C.STATIC: NO_FILES},
    template="envoy.yaml",
    argv=lambda ctx: [
        exe("envoy"),
        "-c", str(ctx.config),
        "--concurrency", str(ctx.workers),
        "--log-level", "warn",
        "--disable-hot-restart",
    ],
    features=frozenset(Feature),
    feature_template="envoy-features.yaml",
    feature_values=features,
    metrics_path="/stats/prometheus",
    feature_tuning=(
        "balanced cells: both origin addresses in the cluster with lb_policy ROUND_ROBIN (default), LEAST_REQUEST "
        "(two random choices), or MAGLEV with a route hash_policy on the X-Client header; no outlier detection (default)",
        f"health: cluster health_checks, HTTP GET {HEALTH_PATH} every {HEALTH_INTERVAL_S}s",
        "limits: the HTTP local_ratelimit filter, one token bucket shared by every worker; per client through route "
        "rate_limits on the X-Client header (or remote_address) and a wildcard descriptor with max_dynamic_descriptors "
        "65536, always_consume_default_token_bucket false",
        "metrics: Envoy always keeps its stats; the admin listener on loopback serves /stats/prometheus",
        "trusted: xff_num_trusted_hops 1 with use_remote_address",
    ),
    tuning=(
        "--concurrency = profile vCPUs; --log-level warn; no access log and no admin listener",
        "--disable-hot-restart: no shared-memory region that would collide with another instance",
        "edge best practices: overload manager (2 GiB heap, 50000 downstream connections), per-connection buffer 32 KiB, "
        "idle_timeout 3600s, stream_idle_timeout and request_timeout 300s, HTTP/2 100 streams with 64 KiB / 1 MiB windows, "
        "use_remote_address, path normalization, reject headers with underscores",
        "listener runtime connection_limit 50000 and tcp_backlog_size 4096; SO_REUSEPORT is the Linux default",
        "upstream cluster: explicit HTTP/1.1, per-worker connection pool, idle_timeout 60s; "
        "circuit breakers raised to 100000 (defaults of 1024 pending requests would 503 the 10k-connection scenario)",
        "TLS 1.3 minimum, ALPN h2,http/1.1; default ciphers and stateless session tickets",
        "QUIC listener with codec HTTP3 and prefer_gro; alt-svc added on TCP TLS responses as in the vendor's QUIC example",
    ),
    sources=(
        "https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/load_balancers",
        "https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/local_rate_limit_filter",
        "https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/health_checking",
        "https://www.envoyproxy.io/docs/envoy/latest/operations/admin#get--stats-prometheus",
        "https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-for",
        "https://www.envoyproxy.io/docs/envoy/latest/configuration/best_practices/edge",
        "https://www.envoyproxy.io/docs/envoy/latest/operations/cli",
        "https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/circuit_breaking",
        "https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/connection_pooling",
        "https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/listener/v3/listener.proto",
        "https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/http/http3",
        "https://github.com/envoyproxy/envoy/blob/main/configs/envoyproxy_io_proxy_http3_downstream.yaml",
    ),
)
