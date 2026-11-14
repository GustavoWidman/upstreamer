from ..scenarios import Capability as C
from ..servers import ALL, NO_FILES, Server, exe

SERVER = Server(
    name="haproxy",
    tool="haproxy",
    capabilities=ALL - {C.STATIC},
    not_applicable={C.STATIC: NO_FILES},
    template="haproxy.cfg",
    argv=lambda ctx: [exe("haproxy"), "-f", str(ctx.config), "-db"],
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
