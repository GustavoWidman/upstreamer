from ..scenarios import Capability as C
from ..servers import ALL, Server, exe

SERVER = Server(
    name="ferron",
    tool="ferron",
    capabilities=ALL - {C.H3},
    not_applicable={
        C.H3: "ferron 2.7.0 sends STOP_SENDING (code 0) on every HTTP/3 request stream; h2load counts each request as failed",
    },
    template="ferron.kdl",
    argv=lambda ctx: [exe("ferron"), "--config", str(ctx.config)],
    tuning=(
        "one request handler thread per CPU in the affinity mask (available_parallelism honours taskset); ferron has no thread directive",
        "no access log (default); error log to stderr",
        "protocols h1 h2 h3; Alt-Svc is sent by default when h3 is on",
        "upstream: proxy_keepalive on, HTTP/1.1, idle_timeout 60 s, proxy_concurrent_conns 16384, no per-backend limit (all defaults)",
        "buffer_request and buffer_response off (default): bodies stream",
        "TLS 1.3 only, default rustls cipher suites; ocsp_stapling off (the bench certificate has no responder)",
        "io_uring auto (default); listen backlog is net.core.somaxconn (ferron listens with -1)",
        "client keep-alive: hyper's 30 s header-read timeout closes idle connections; ferron does not expose it",
        "static: default etag and compression; h2load sends no Accept-Encoding, so files go out uncompressed",
    ),
    sources=(
        "https://ferron.sh/docs/configuration/core-directives",
        "https://ferron.sh/docs/configuration/reverse-proxying",
        "https://ferron.sh/docs/configuration/security-tls",
        "https://ferron.sh/docs/configuration/observability-logging",
        "https://ferron.sh/docs/configuration/static-content",
    ),
)
