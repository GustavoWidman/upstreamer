from ..scenarios import (
    CLIENT_HEADER,
    LIMIT_CLIENT_RATE,
    LIMIT_CONST_RATE,
    METRICS_PATH,
    Feature,
)
from ..servers import ALL, Context, Server, exe

F = Feature
HEADER_VAR = "$http_" + CLIENT_HEADER.lower().replace("-", "_")


def features(ctx: Context) -> dict[str, str]:
    f = ctx.features
    v = ctx.values()
    http, location, servers = [], [], []
    upstream = [f"        server {v['origin']};"]
    if f & {F.LB_ROUND_ROBIN, F.LB_LEAST, F.LB_HASH}:
        upstream.append(f"        server {v['origin2']};")
    if F.LB_LEAST in f:
        upstream.insert(0, "        least_conn;")
    if F.LB_HASH in f:
        upstream.insert(0, f"        hash {HEADER_VAR} consistent;")
    if F.TRUSTED in f:
        http += [f"    set_real_ip_from {v['host']};", "    real_ip_header X-Forwarded-For;"]
    if F.LIMIT_CLIENT in f:
        key = "$binary_remote_addr" if F.TRUSTED in f else HEADER_VAR
        http.append(f"    limit_req_zone {key} zone=client:16m rate={LIMIT_CLIENT_RATE}r/s;")
        location.append(f"            limit_req zone=client burst={LIMIT_CLIENT_RATE} nodelay;")
    if F.LIMIT_CONST in f:
        http.append(f'    limit_req_zone "all" zone=all:1m rate={LIMIT_CONST_RATE}r/s;')
        location.append(f"            limit_req zone=all burst={LIMIT_CONST_RATE} nodelay;")
    if F.METRICS in f:
        servers.append(
            f"    server {{\n        listen {v['host']}:{v['admin_port']};\n"
            f"        location = {METRICS_PATH} {{\n            stub_status;\n        }}\n    }}"
        )
    return {
        "http_extra": "\n".join(http),
        "upstream": "\n".join(upstream),
        "location_extra": "\n".join(location),
        "servers_extra": "\n".join(servers),
    }


SERVER = Server(
    name="nginx",
    tool="nginx",
    capabilities=ALL,
    not_applicable={},
    template="nginx.conf",
    argv=lambda ctx: [exe("nginx"), "-c", str(ctx.config), "-p", str(ctx.run_dir), "-e", "stderr"],
    tuning=(
        "worker_processes = profile vCPUs; worker_connections 65536; worker_rlimit_nofile",
        "access_log off; error_log at warn",
        "upstream keepalive 256 with proxy_http_version 1.1 and an empty Connection header",
        "keepalive_requests 1000000 on client and upstream connections (default 1000 closes connections mid-run)",
        "listen ... reuseport backlog=4096 on every listener",
        "TLS 1.3 only, shared session cache; http2 on; http3 on with quic_gso and Alt-Svc",
        "proxy_request_buffering off and proxy_max_temp_file_size 0: stream bodies instead of spooling to disk",
        "static: sendfile, tcp_nopush, open_file_cache",
    ),
    features=frozenset(Feature),
    feature_template="nginx-features.conf",
    feature_values=features,
    feature_tuning=(
        "balanced cells: both origin addresses in the upstream block (round robin by default), least_conn, "
        "or hash $http_x_client consistent (ketama); passive health at its defaults (max_fails 1, fail_timeout 10s)",
        "health: nginx open source has no active health checks (they are nginx Plus); its passive checks stand in",
        f"limits: limit_req_zone on $http_x_client (or $binary_remote_addr after realip) at {LIMIT_CLIENT_RATE}r/s, "
        f"or on a constant key at {LIMIT_CONST_RATE}r/s; limit_req with burst equal to the rate and nodelay",
        f"metrics: stub_status (nginx open source's only metrics) at {METRICS_PATH} on a loopback server",
        "trusted: realip with set_real_ip_from 127.0.0.1 and real_ip_header X-Forwarded-For",
    ),
    sources=(
        "https://nginx.org/en/docs/http/ngx_http_upstream_module.html#keepalive",
        "https://nginx.org/en/docs/http/ngx_http_upstream_module.html#hash",
        "https://nginx.org/en/docs/http/ngx_http_limit_req_module.html",
        "https://nginx.org/en/docs/http/ngx_http_stub_status_module.html",
        "https://nginx.org/en/docs/http/ngx_http_realip_module.html",
        "https://www.f5.com/company/blog/nginx/tuning-nginx",
        "https://www.f5.com/company/blog/nginx/socket-sharding-nginx-release-1-9-1",
        "https://nginx.org/en/docs/http/ngx_http_v3_module.html",
        "https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_request_buffering",
    ),
)
