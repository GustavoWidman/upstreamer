from ..scenarios import Capability as C
from ..servers import ALL, Server, exe

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
    sources=(
        "https://nginx.org/en/docs/http/ngx_http_upstream_module.html#keepalive",
        "https://www.f5.com/company/blog/nginx/tuning-nginx",
        "https://www.f5.com/company/blog/nginx/socket-sharding-nginx-release-1-9-1",
        "https://nginx.org/en/docs/http/ngx_http_v3_module.html",
        "https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_request_buffering",
    ),
)
