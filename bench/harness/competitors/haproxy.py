from ..scenarios import (
    CLIENT_HEADER,
    HEALTH_INTERVAL_S,
    HEALTH_PATH,
    LIMIT_CLIENT_RATE,
    LIMIT_CONST_RATE,
    METRICS_PATH,
    Feature,
)
from ..scenarios import Capability as C
from ..servers import ALL, NO_FILES, Context, Server, exe

F = Feature


def features(ctx: Context) -> dict[str, str]:
    f = ctx.features
    v = ctx.values()
    frontend, backend, sections = [], [], []
    check = f" check inter {HEALTH_INTERVAL_S}s" if F.HEALTH in f else ""
    if F.HEALTH in f:
        backend.append(f"    option httpchk GET {HEALTH_PATH}")
    if F.LB_LEAST in f:
        backend.append("    balance leastconn")
    if F.LB_HASH in f:
        backend += [f"    balance hdr({CLIENT_HEADER})", "    hash-type consistent"]
    backend.append(f"    server origin {v['origin']}{check}")
    if f & {F.LB_ROUND_ROBIN, F.LB_LEAST, F.LB_HASH}:
        backend.append(f"    server origin2 {v['origin2']}{check}")
    if F.TRUSTED in f:
        frontend.append(f"    http-request set-src hdr_ip(x-forwarded-for,-1) if {{ src {v['host']} }}")
    if F.LIMIT_CLIENT in f:
        if F.TRUSTED in f:
            table, key = "type ip", "src"
        else:
            table, key = "type string len 32", f"req.hdr({CLIENT_HEADER})"
        sections.append(f"backend client_rate\n    stick-table {table} size 64k expire 10s store http_req_rate(1s)")
        frontend += [
            f"    http-request track-sc0 {key} table client_rate",
            f"    http-request deny deny_status 429 if {{ sc_http_req_rate(0) gt {LIMIT_CLIENT_RATE} }}",
        ]
    if F.LIMIT_CONST in f:
        sections.append("backend all_rate\n    stick-table type integer size 1 expire 10s store http_req_rate(1s)")
        frontend += [
            "    http-request track-sc0 int(1) table all_rate",
            f"    http-request deny deny_status 429 if {{ sc_http_req_rate(0) gt {LIMIT_CONST_RATE} }}",
        ]
    if F.METRICS in f:
        sections.append(
            f"frontend metrics\n    bind {v['host']}:{v['admin_port']}\n"
            f"    http-request use-service prometheus-exporter if {{ path {METRICS_PATH} }}"
        )
    return {
        "frontend_extra": "\n".join(frontend),
        "backend": "\n".join(backend),
        "sections_extra": "\n\n".join(sections),
    }


SERVER = Server(
    name="haproxy",
    tool="haproxy",
    capabilities=ALL - {C.STATIC},
    not_applicable={C.STATIC: NO_FILES},
    template="haproxy.cfg",
    argv=lambda ctx: [exe("haproxy"), "-f", str(ctx.config), "-db"],
    features=frozenset(Feature),
    feature_template="haproxy-features.cfg",
    feature_values=features,
    feature_tuning=(
        "balanced cells: both origin addresses in the backend with balance roundrobin (default), leastconn, "
        "or hdr(X-Client) with hash-type consistent; passive health is haproxy's observe-less default",
        f"health: option httpchk GET {HEALTH_PATH}, check inter {HEALTH_INTERVAL_S}s on each server",
        "limits: a stick table storing http_req_rate(1s), tracked by track-sc0 on req.hdr(X-Client) (or src after "
        f"set-src), or on int(1) for one bucket; deny 429 above {LIMIT_CLIENT_RATE} or {LIMIT_CONST_RATE} per second",
        f"metrics: the built-in Prometheus exporter (USE_PROMEX) on a loopback frontend at {METRICS_PATH}",
        "trusted: http-request set-src hdr_ip(x-forwarded-for,-1) if the peer is 127.0.0.1",
    ),
    tuning=(
        "nbthread = profile vCPUs",
        "global and frontend maxconn 100000 (frontend default is far below 10k idle connections)",
        "no log directive: no access or error logging",
        "bind backlog 4096 on TCP listeners",
        "option http-keep-alive with default http-reuse safe; server connections pooled without a cap",
        "timeout client / server / http-keep-alive 75s",
        "ssl-default-bind-options ssl-min-ver TLSv1.3; default ciphersuites and built-in session cache",
        "TCP bind alpn h2,http/1.1; QUIC bind quic4@ alpn h3 with alt-svc on TLS responses",
        "bodies stream through HTX; no http-buffer-request",
    ),
    sources=(
        "https://docs.haproxy.org/3.3/configuration.html#4.2-balance",
        "https://docs.haproxy.org/3.3/configuration.html#4.2-stick-table",
        "https://docs.haproxy.org/3.3/configuration.html#4.2-http-request%20track-sc0",
        "https://docs.haproxy.org/3.3/configuration.html#4.2-option%20httpchk",
        "https://www.haproxy.com/blog/haproxy-exposes-a-prometheus-metrics-endpoint",
        "https://www.haproxy.com/blog/four-examples-of-haproxy-rate-limiting",
        "https://docs.haproxy.org/3.3/configuration.html#3.1-nbthread",
        "https://docs.haproxy.org/3.3/configuration.html#3.2-maxconn",
        "https://docs.haproxy.org/3.3/configuration.html#5.1-backlog",
        "https://docs.haproxy.org/3.3/configuration.html#4.2-http-reuse",
        "https://docs.haproxy.org/3.3/configuration.html#3.1-ssl-default-bind-options",
        "https://docs.haproxy.org/3.3/configuration.html#quic4",
        "https://www.haproxy.com/blog/how-to-enable-quic-load-balancing-on-haproxy",
        "https://www.haproxy.com/blog/http-keep-alive-pipelining-multiplexing-and-connection-pooling",
        "https://docs.haproxy.org/3.3/management.html#3",
    ),
)
