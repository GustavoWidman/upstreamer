import os

from ..scenarios import Capability as C
from ..servers import ALL, Server, exe

# The event MPM closes every keep-alive connection of a child whose workers are
# all busy. 1024 threads per child absorb the burst of 10k TLS handshakes in
# idle-tls without closing the connections already admitted.
THREADS_PER_CHILD = 1024


def env(ctx) -> dict[str, str]:
    # httpd has no arithmetic in its config; derive the totals here and pass
    # them as ${VAR} references. One listener bucket per child process.
    return {
        "HTTPD_THREADS_PER_CHILD": str(THREADS_PER_CHILD),
        "HTTPD_MAX_REQUEST_WORKERS": str(ctx.workers * THREADS_PER_CHILD),
        "HTTPD_LISTEN_CORES_BUCKETS_RATIO": str(max(1, (os.cpu_count() or 1) // ctx.workers)),
    }


SERVER = Server(
    name="httpd",
    tool="httpd",
    capabilities=ALL - {C.H3},
    not_applicable={C.H3: "httpd has no HTTP/3 or QUIC support"},
    template="httpd.conf",
    argv=lambda ctx: [exe("httpd"), "-DFOREGROUND", "-f", str(ctx.config)],
    env=env,
    tuning=(
        "event MPM: StartServers = ServerLimit = profile vCPUs, ThreadLimit = ThreadsPerChild 1024, MaxRequestWorkers = MaxSpareThreads = vCPUs x 1024, MinSpareThreads 1 (no process churn)",
        "AsyncRequestWorkerFactor 16: per-child connection cap 1024 + 16 x idle workers admits all 10k idle-tls connections even on one child",
        "MaxConnectionsPerChild 0; KeepAlive On, MaxKeepAliveRequests 0 (default 100 closes connections mid-run), KeepAliveTimeout 75",
        "ListenBacklog 4096; ListenCoresBucketsRatio = online cores / vCPUs so each child gets its own SO_REUSEPORT listener bucket",
        "no CustomLog (access log off); ErrorLog stderr at LogLevel warn",
        "mod_proxy_http pool: reuse on by default, max = ThreadsPerChild (1024) connections per child",
        "mod_proxy_http streams Content-Length request bodies and responses; LimitRequestBody default 1 GiB",
        "TLS 1.3 only (SSLProtocol -all +TLSv1.3); shmcb SSLSessionCache; session tickets on by default",
        "Protocols h2 http/1.1 on TLS listeners via mod_http2",
        "static: EnableSendfile On, mime types from the package's conf/mime.types",
    ),
    sources=(
        "https://httpd.apache.org/docs/2.4/mod/event.html#asyncrequestworkerfactor",
        "https://httpd.apache.org/docs/2.4/mod/mpm_common.html",
        "https://httpd.apache.org/docs/2.4/misc/perf-tuning.html",
        "https://httpd.apache.org/docs/2.4/mod/core.html#maxkeepaliverequests",
        "https://httpd.apache.org/docs/2.4/mod/mod_proxy.html#workers",
        "https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslsessioncache",
        "https://httpd.apache.org/docs/2.4/mod/mod_http2.html",
    ),
)
