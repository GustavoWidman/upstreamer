from ..scenarios import Capability as C
from ..servers import ALL, NO_FILES, Server, exe

SERVER = Server(
    name="envoy",
    tool="envoy",
    capabilities=ALL - {C.STATIC},
    not_applicable={C.STATIC: NO_FILES},
    template="envoy.yaml",
    argv=lambda ctx: [
        exe("envoy"),
        "-c", str(ctx.config),
        "--concurrency", str(ctx.workers),
        "--log-level", "warn",
        "--disable-hot-restart",
    ],
    tuning=(
        "--concurrency = profile vCPUs; --log-level warn; no access log and no admin listener",
        "--disable-hot-restart: no shared-memory region that would collide with another instance",
        "edge best practices: overload manager (2 GiB heap, 50000 downstream connections), per-connection buffer 32 KiB, "
        "idle_timeout 3600s, stream_idle_timeout and request_timeout 300s, HTTP/2 100 streams with 64 KiB / 1 MiB windows, "
        "use_remote_address, path normalization, reject headers with underscores",
        "listener runtime connection_limit 50000 and tcp_backlog_size 4096; SO_REUSEPORT is the Linux default",
        "upstream cluster: explicit HTTP/1.1, per-worker connection pool, idle_timeout 60s; "
        "circuit breakers raised to 100000 (defaults of 1024 pending requests would 503 the 10k-connection scenario)",
        "TLS 1.3 minimum, ALPN h2,http/1.1; default ciphers and stateless session tickets",
        "QUIC listener with codec HTTP3 and prefer_gro; alt-svc added on TCP TLS responses as in the vendor's QUIC example",
    ),
    sources=(
        "https://www.envoyproxy.io/docs/envoy/latest/configuration/best_practices/edge",
        "https://www.envoyproxy.io/docs/envoy/latest/operations/cli",
        "https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/circuit_breaking",
        "https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/connection_pooling",
        "https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/listener/v3/listener.proto",
        "https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/http/http3",
        "https://github.com/envoyproxy/envoy/blob/main/configs/envoyproxy_io_proxy_http3_downstream.yaml",
    ),
)
