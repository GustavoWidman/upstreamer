from ..scenarios import (
    CLIENT_HEADER,
    HEALTH_INTERVAL_S,
    HEALTH_PATH,
    LIMIT_CLIENT_RATE,
    LIMIT_CONST_RATE,
    Feature,
)
from ..scenarios import Capability as C
from ..servers import ALL, NO_FILES, TEMPLATES, Context, Server, exe, render

F = Feature


def _argv(ctx: Context) -> list[str]:
    name = "traefik-dynamic-features.yml" if ctx.features else "traefik-dynamic.yml"
    dynamic = (TEMPLATES / name).read_text()
    (ctx.run_dir / name).write_text(render(dynamic, SERVER.config_values(ctx)))
    return [exe("traefik"), f"--configFile={ctx.config}"]


def features(ctx: Context) -> dict[str, str]:
    f = ctx.features
    v = ctx.values()
    out = dict.fromkeys(
        ["forwarded", "entrypoints_extra", "static_extra", "router_extra", "lb_extra", "servers_extra", "middlewares"], ""
    )
    if f & {F.LB_ROUND_ROBIN, F.LB_LEAST}:
        out["servers_extra"] = f'          - url: "http://{v["origin2"]}"'
    lb = []
    if F.LB_LEAST in f:
        lb.append("        strategy: p2c")
    if F.HEALTH in f:
        lb.append(f"        healthCheck:\n          path: {HEALTH_PATH}\n          interval: {HEALTH_INTERVAL_S}s")
    out["lb_extra"] = "\n".join(lb)
    if F.TRUSTED in f:
        out["forwarded"] = f'    forwardedHeaders:\n      trustedIPs: ["{v["host"]}/32"]'
    criterion = None
    if F.LIMIT_CLIENT in f:
        rate = LIMIT_CLIENT_RATE
        criterion = "ipStrategy:\n            depth: 1" if F.TRUSTED in f else f"requestHeaderName: {CLIENT_HEADER}"
    if F.LIMIT_CONST in f:
        rate, criterion = LIMIT_CONST_RATE, "requestHost: true"
    if criterion:
        out["router_extra"] = "      middlewares: [limit]"
        out["middlewares"] = (
            f"  middlewares:\n    limit:\n      rateLimit:\n        average: {rate}\n        period: 1s\n"
            f"        burst: {rate}\n        sourceCriterion:\n          {criterion}"
        )
    if F.METRICS in f:
        out["entrypoints_extra"] = f'  metrics:\n    address: "{v["host"]}:{v["admin_port"]}"'
        out["static_extra"] = "metrics:\n  prometheus:\n    entryPoint: metrics"
    return out


SERVER = Server(
    name="traefik",
    tool="traefik",
    capabilities=ALL - {C.STATIC},
    not_applicable={C.STATIC: NO_FILES},
    template="traefik.yml",
    argv=_argv,
    env=lambda ctx: {"GOMAXPROCS": str(ctx.workers)},
    features=frozenset(Feature) - {F.LB_HASH},
    feature_na={F.LB_HASH: "no hash of a request header among its load-balancing strategies (wrr, p2c, hrw on the client IP)"},
    feature_template="traefik-features.yml",
    feature_values=features,
    feature_tuning=(
        "balanced cells: both origin addresses in the service's loadBalancer, strategy wrr (default) or p2c "
        "(two random choices, fewer in flight: the least-requests policy); no passive health in traefik",
        f"health: loadBalancer.healthCheck path {HEALTH_PATH}, interval {HEALTH_INTERVAL_S}s",
        "limits: the rateLimit middleware with average and burst equal to the rate, period 1s, sourceCriterion "
        "requestHeaderName X-Client (or ipStrategy depth 1 behind a trusted peer), or requestHost for one bucket",
        "metrics: metrics.prometheus on a loopback entryPoint, /metrics",
        "trusted: entryPoints forwardedHeaders.trustedIPs 127.0.0.1/32",
    ),
    tuning=(
        "GOMAXPROCS = profile vCPUs",
        "no accessLog, api, metrics or ping; log level WARN; version check and usage reporting off",
        "entryPoint idleTimeout 75s; readTimeout and keepAliveMaxRequests at defaults (60s, unlimited)",
        "serversTransport maxIdleConnsPerHost 256 (default 200)",
        "TLS option minVersion VersionTLS13; default cipher suites and ALPN h2, http/1.1",
        "default store defaultCertificate, served when no SNI matches",
        "http3 on the TLS entryPoint; Alt-Svc advertised by default",
        "file provider with watch off",
    ),
    sources=(
        "https://doc.traefik.io/traefik/reference/routing-configuration/http/load-balancing/service/",
        "https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/ratelimit/",
        "https://doc.traefik.io/traefik/reference/install-configuration/observability/metrics/",
        "https://doc.traefik.io/traefik/reference/install-configuration/entrypoints/",
        "https://doc.traefik.io/traefik/reference/install-configuration/observability/logs-and-accesslogs/",
        "https://doc.traefik.io/traefik/reference/routing-configuration/http/load-balancing/serverstransport/",
        "https://doc.traefik.io/traefik/reference/routing-configuration/http/tls/tls-options/",
        "https://doc.traefik.io/traefik/reference/routing-configuration/http/tls/tls-certificates/",
        "https://doc.traefik.io/traefik/reference/install-configuration/providers/others/file/",
        "https://pkg.go.dev/runtime#hdr-Environment_Variables",
    ),
)
