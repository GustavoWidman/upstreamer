from ..scenarios import Capability as C
from ..servers import ALL, Server, exe

SERVER = Server(
    name="lighttpd",
    tool="lighttpd",
    capabilities=ALL - {C.H3},
    not_applicable={C.H3: "lighttpd has no HTTP/3 or QUIC support"},
    template="lighttpd.conf",
    argv=lambda ctx: [exe("lighttpd"), "-D", "-f", str(ctx.config)],
    tuning=(
        "server.max-worker = profile vCPUs (the vendor recommends 0, one event loop, but a single process cannot use a multi-vCPU profile)",
        "server.max-fds 65536, server.max-connections 16384 per worker process; server.listen-backlog 4096",
        "server.max-keep-alive-requests 65535 (the setting's type maximum; default 1000 closes connections mid-run)",
        "server.max-keep-alive-idle 75 s (default 5 s), server.max-read-idle 60 s",
        "server.stream-request-body 2 and server.stream-response-body 2: stream 1 MiB bodies with minimal buffering instead of spooling to temp files",
        "mod_accesslog not loaded (access log off); errors to stderr in foreground mode",
        "mod_proxy speaks HTTP/1.1 to the origin but sends Connection: close on every request: lighttpd has no upstream keep-alive pool",
        "TLS 1.3 only via ssl.openssl.ssl-conf-cmd MinProtocol; default cipher suites and session tickets",
        "HTTP/2 built in and enabled by default (server.h2proto) on every TLS socket",
    ),
    sources=(
        "https://redmine.lighttpd.net/projects/lighttpd/wiki/Docs_Performance",
        "https://redmine.lighttpd.net/projects/lighttpd/wiki/Server_max-workerDetails",
        "https://redmine.lighttpd.net/projects/lighttpd/wiki/Server_max-keep-alive-requestsDetails",
        "https://redmine.lighttpd.net/projects/lighttpd/wiki/Server_stream-request-bodyDetails",
        "https://redmine.lighttpd.net/projects/lighttpd/wiki/Mod_proxy",
        "https://redmine.lighttpd.net/projects/lighttpd/wiki/Docs_SSL",
        "https://git.lighttpd.net/lighttpd/lighttpd1.4/src/tag/lighttpd-1.4.82/src/mod_proxy.c",
    ),
)
