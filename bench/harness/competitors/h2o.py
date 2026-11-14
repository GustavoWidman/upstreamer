from ..servers import ALL, Server, exe

SERVER = Server(
    name="h2o",
    tool="h2o",
    capabilities=ALL,
    not_applicable={},
    template="h2o.yaml",
    argv=lambda ctx: [exe("h2o"), "-c", str(ctx.config)],
    tuning=(
        "num-threads = profile vCPUs; tcp-reuseport ON (default OFF)",
        "max-connections 65536 (default 1024 refuses most of the 10k idle-tls connections)",
        "no access-log; error-log to stderr",
        "proxy.timeout.keepalive 60000 ms (default 2000 drops pooled origin connections between bursts); upstream pool is unbounded",
        "http1-request-timeout and http1-request-io-timeout 75 s, http2-idle-timeout 75 s (defaults 10/5/10 s close idle keep-alive connections)",
        "listen backlog is compiled in as 65535 (H2O_SOMAXCONN), capped by net.core.somaxconn",
        "TLS 1.3 only via minimum-version; default cipher suites; default ssl-session-resumption (internal cache and tickets)",
        "HTTP/3 on a type: quic listener sharing the TLS listener's settings, with the alt-svc header the vendor example pairs with it",
        "request and response bodies stream in memory: temp-buffer-threshold (32 MiB default) is above the 1 MiB bodies",
    ),
    sources=(
        "https://h2o.examp1e.net/configure/base_directives.html",
        "https://h2o.examp1e.net/configure/proxy_directives.html#proxy.timeout.keepalive",
        "https://h2o.examp1e.net/configure/http1_directives.html",
        "https://h2o.examp1e.net/configure/http2_directives.html#http2-idle-timeout",
        "https://h2o.examp1e.net/configure/http3_directives.html",
        "https://github.com/h2o/h2o/blob/master/examples/h2o/h2o.conf",
    ),
)
