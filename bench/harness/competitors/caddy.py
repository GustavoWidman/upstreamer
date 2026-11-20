from ..scenarios import CLIENT_HEADER, HEALTH_INTERVAL_S, HEALTH_PATH, METRICS_PATH, Feature
from ..servers import ALL, Context, Server, exe

F = Feature
NO_LIMIT = "rate limiting is the third-party caddy-ratelimit module, not in the pinned build"


def features(ctx: Context) -> dict[str, str]:
    f = ctx.features
    v = ctx.values()
    upstreams = [v["origin"]]
    glob, servers, proxy, sites = [], [], [], []
    if f & {F.LB_ROUND_ROBIN, F.LB_LEAST, F.LB_HASH}:
        upstreams.append(v["origin2"])
    if F.LB_ROUND_ROBIN in f:
        proxy.append("\t\tlb_policy round_robin")
    if F.LB_LEAST in f:
        proxy.append("\t\tlb_policy least_conn")
    if F.LB_HASH in f:
        proxy.append(f"\t\tlb_policy header {CLIENT_HEADER}")
    if F.HEALTH in f:
        proxy += [f"\t\thealth_uri {HEALTH_PATH}", f"\t\thealth_interval {HEALTH_INTERVAL_S}s"]
    if F.TRUSTED in f:
        servers += [f"\t\ttrusted_proxies static {v['host']}/32", "\t\tclient_ip_headers X-Forwarded-For"]
    if F.METRICS in f:
        glob.append("\tmetrics")
        sites.append(f"\nhttp://:{v['admin_port']} {{\n\tbind {v['host']}\n\tmetrics {METRICS_PATH}\n}}")
    return {
        "upstreams": " ".join(upstreams),
        "global_extra": "\n".join(glob),
        "servers_extra": "\n".join(servers),
        "proxy_extra": "\n".join(proxy),
        "sites_extra": "\n".join(sites),
    }


SERVER = Server(
    name="caddy",
    tool="caddy",
    capabilities=ALL,
    not_applicable={},
    template="Caddyfile",
    argv=lambda ctx: [exe("caddy"), "run", "--config", str(ctx.config), "--adapter", "caddyfile"],
    env=lambda ctx: {
        "GOMAXPROCS": str(ctx.workers),
        "XDG_CONFIG_HOME": str(ctx.run_dir),
        "XDG_DATA_HOME": str(ctx.run_dir),
    },
    features=frozenset({F.LB_ROUND_ROBIN, F.LB_LEAST, F.LB_HASH, F.HEALTH, F.METRICS, F.TRUSTED}),
    feature_na={F.LIMIT_CLIENT: NO_LIMIT, F.LIMIT_CONST: NO_LIMIT},
    feature_template="Caddyfile-features",
    feature_values=features,
    feature_tuning=(
        "balanced cells: both origin addresses in reverse_proxy with lb_policy round_robin, least_conn, "
        "or header X-Client (rendezvous hashing); passive health at its default (off)",
        f"health: health_uri {HEALTH_PATH}, health_interval {HEALTH_INTERVAL_S}s",
        f"metrics: the global metrics option (HTTP request metrics) and the metrics handler at {METRICS_PATH} "
        "on a loopback site (the admin API stays off)",
        "trusted: servers trusted_proxies static 127.0.0.1/32 with client_ip_headers X-Forwarded-For",
    ),
    tuning=(
        "GOMAXPROCS = profile vCPUs",
        "admin off, persist_config off; storage and XDG dirs in the run dir",
        "no access log; runtime log level WARN",
        "auto_https disable_redirects: no HTTP->HTTPS redirect and no listener on port 80",
        "tls with the given cert, protocols tls1.3; default ciphers and session tickets",
        "server idle timeout 75s; default protocols h1 h2 h3 with Alt-Svc sent by default",
        "reverse_proxy transport http versions 1.1, keepalive 75s, keepalive_idle_conns(_per_host) 256 (default per host is 32)",
        "bodies stream: request_buffers and response_buffers left at 0",
        "static: file_server rooted at the static dir",
    ),
    sources=(
        "https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#load-balancing",
        "https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#active-health-checks",
        "https://caddyserver.com/docs/caddyfile/directives/metrics",
        "https://caddyserver.com/docs/caddyfile/options#metrics",
        "https://caddyserver.com/docs/caddyfile/options#trusted-proxies",
        "https://caddyserver.com/docs/caddyfile/options",
        "https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#the-http-transport",
        "https://caddyserver.com/docs/caddyfile/directives/tls",
        "https://caddyserver.com/docs/automatic-https#activation",
        "https://caddyserver.com/docs/caddyfile/directives/file_server",
        "https://caddyserver.com/docs/conventions#data-directory",
        "https://pkg.go.dev/runtime#hdr-Environment_Variables",
    ),
)
